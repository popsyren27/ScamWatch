"""
tor_manager.py — Tor and anonymity checks (personal notes).

High level: rotate circuits and verify the exit IP is not my host IP. If it
looks like traffic is leaking, abort the scan — that's the whole point.

Quick reminders / TODOs:
- NEWNYM via stem when available; keep leak check strict.
- If I see repeated stem auth failures, re-check Tor control port credentials.
"""

# NOTE TO FUTURE-ME: Tor is magical but temperamental. If you see traffic leak,
# it probably means Tor or my code is sad — both fixable with patience and tea.

from __future__ import annotations

import asyncio
import contextlib
from typing import Optional

import httpx
from pydantic import StrictStr, validate_call

from config import (
    HTTP_TIMEOUT_SECONDS,
    IP_ECHO_SERVICES,
    TOR_CONTROL_PASSWORD,
    TOR_CONTROL_PORT,
    TOR_NEWNYM_SETTLE_SECONDS,
    TOR_PROXY_URL,
    USER_AGENT,
)
from models import ProxyIdentity
from modules.logging_setup import get_logger

log = get_logger("proxy.tor")


class AnonymityError(RuntimeError):
    """Raised when we cannot prove traffic is anonymised — fail closed."""


def build_client(direct: bool = False) -> httpx.AsyncClient:
    """Construct an httpx.AsyncClient — Tor-routed by default.

    ``direct=True`` builds a NON-anonymised client with no proxy. It exists only
    so the loopback 'local testing' mode can reach 127.0.0.1 (which Tor cannot
    route). Callers MUST gate direct=True behind ``util.is_loopback`` — nothing
    here trusts the flag for a remote host.
    """
    proxy: Optional[str] = None if direct else TOR_PROXY_URL
    return httpx.AsyncClient(
        proxy=proxy,
        headers={"User-Agent": USER_AGENT},
        timeout=HTTP_TIMEOUT_SECONDS,
        follow_redirects=True,
    )


def build_tor_client() -> httpx.AsyncClient:
    """Back-compatible Tor-pinned client (``build_client(direct=False)``)."""
    return build_client(direct=False)


def local_identity() -> ProxyIdentity:
    """Synthesise a ProxyIdentity for direct loopback testing.

    Explicitly NOT anonymous — it records that Tor was bypassed for a local
    target so the report never misrepresents the routing.
    """
    return ProxyIdentity(
        host_ip="localhost", exit_ip="direct (no Tor)",
        is_anonymous=False, circuit_renewed=False,
    )


async def _probe_ip_echo_services(client: httpx.AsyncClient, label: str) -> Optional[str]:
    """Ask each configured echo service for our IP, stop at the first good answer.

    One shared loop for both host-IP and exit-IP checks, so I only had to get
    this fiddly bit right once instead of twice.
    """
    for service in IP_ECHO_SERVICES:
        try:
            resp = await client.get(service)
            if resp.status_code == 200 and resp.text.strip():
                ip: str = resp.text.strip()
                log.info("Discovered %s IP via %s: %s", label, service, ip)
                return ip
        except httpx.HTTPError as exc:
            log.warning("%s-IP echo %s failed: %s", label, service, exc)
        except Exception as exc:
            # Keep trying the next service — one flaky echo shouldn't sink us.
            log.error("Unexpected error with service %s: %s", service, exc)
    return None


async def _discover_host_ip() -> Optional[str]:
    """Find the host's REAL (non-Tor) IP for later leak comparison.

    This is the only deliberate direct connection in the system, and it touches
    nothing but a neutral echo service. If it fails we return None and the leak
    check treats 'unknown host IP' as untrusted.
    """
    try:
        async with httpx.AsyncClient(
            timeout=HTTP_TIMEOUT_SECONDS, headers={"User-Agent": USER_AGENT}
        ) as direct_client:
            return await _probe_ip_echo_services(direct_client, label="host")
    except httpx.RequestError as exc:
        log.error("Could not establish a direct client for host-IP check: %s", exc)
    except Exception as exc:
        # Any unexpected error while finding host IP should be logged, not raised.
        log.error("Unexpected error during host-IP discovery: %s", exc)
    return None


async def _discover_exit_ip(client: httpx.AsyncClient) -> Optional[str]:
    """Find the IP the outside world sees through Tor."""
    return await _probe_ip_echo_services(client, label="exit")


async def _authenticate_tor_controller(controller: "object") -> None:
    """Log in to the Tor control port, password if we have one, cookie auth otherwise."""
    if TOR_CONTROL_PASSWORD:
        controller.authenticate(password=TOR_CONTROL_PASSWORD)
    else:
        controller.authenticate()


async def renew_circuit() -> bool:
    """Signal Tor for a brand-new circuit (NEWNYM) before a scan.

    Uses the `stem` controller over the control port. Returns True on success.
    A failure is logged but NOT fatal on its own — the subsequent leak check is
    the real gate; a stale-but-still-anonymous circuit is acceptable, a leaked
    one is not.
    """
    controller = None
    try:
        # Imported lazily so the app still boots if `stem` is absent.
        from stem import Signal  # type: ignore
        from stem.control import Controller  # type: ignore

        controller = Controller.from_port(port=TOR_CONTROL_PORT)
        await _authenticate_tor_controller(controller)

        # NEWNYM requests a fresh Tor circuit; wait briefly so the router
        # can build the new path before we probe the exit IP. Short sleep
        # balances convergence against scan latency.
        controller.signal(Signal.NEWNYM)
        log.info("Requested NEWNYM; waiting %.1fs for circuit to settle.",
                  TOR_NEWNYM_SETTLE_SECONDS)
        await asyncio.sleep(TOR_NEWNYM_SETTLE_SECONDS)
        return True
    except ImportError:
        log.warning("`stem` not installed — cannot rotate circuit; continuing "
                    "with the existing one (leak check still enforced).")
        return False
    except Exception as exc:
        # Why: control-port auth issues are common; degrade rather than abort.
        log.warning("Circuit renewal failed: %s", exc)
        return False
    finally:
        # Active cleanup: never leak the control socket.
        if controller is not None:
            with contextlib.suppress(Exception):
                controller.close()


def _ensure_exit_ip_found(exit_ip: Optional[str]) -> None:
    """Fail closed if Tor never told us an exit IP — no exit IP, no proof of anonymity."""
    if not exit_ip:
        raise AnonymityError(
            "Could not determine the Tor exit IP — refusing to scan because "
            "anonymity is unproven (is the Tor daemon running on "
            f"{TOR_PROXY_URL}?)."
        )


def _ensure_no_ip_leak(host_ip: Optional[str], exit_ip: str) -> None:
    """The core fail-safe: if exit IP equals host IP, Tor isn't carrying traffic. Halt."""
    if host_ip is not None and exit_ip == host_ip:
        raise AnonymityError(
            f"CRITICAL IP LEAK: exit IP {exit_ip} equals host IP — traffic "
            "is bypassing Tor. Halting to protect the operator."
        )


def _build_identity(host_ip: Optional[str], exit_ip: str, renewed: bool) -> ProxyIdentity:
    """Package the verified IPs into a ProxyIdentity, conservative about 'anonymous'."""
    # If we couldn't discover the host IP, be conservative: assume the
    # exit is anonymous unless it explicitly matches a discovered host IP.
    is_anon: bool = host_ip is None or exit_ip != host_ip
    return ProxyIdentity(
        host_ip=host_ip or "unknown",
        exit_ip=exit_ip,
        is_anonymous=bool(is_anon),
        circuit_renewed=renewed,
    )


@validate_call
async def acquire_anonymous_identity(target_url: StrictStr) -> ProxyIdentity:
    """Top-level Phase-1 entrypoint: rotate, verify, and prove anonymity.

    Raises:
        AnonymityError: if anonymity cannot be PROVEN. We fail closed — the scan
        must not proceed unless the exit IP is confirmed to differ from the host
        IP. ``target_url`` is accepted for audit logging context.
    """
    log.info("Acquiring anonymous identity for target: %s", target_url)
    renewed: bool = await renew_circuit()

    client: httpx.AsyncClient = build_tor_client()
    try:
        host_ip: Optional[str] = await _discover_host_ip()
        exit_ip: Optional[str] = await _discover_exit_ip(client)

        # If we could not determine an exit IP over Tor, anonymity is unproven.
        # Treat missing exit IP as a fatal condition to avoid blind scans.
        _ensure_exit_ip_found(exit_ip)
        assert exit_ip is not None  # narrowed by the check above, for type checkers

        _ensure_no_ip_leak(host_ip, exit_ip)

        identity: ProxyIdentity = _build_identity(host_ip, exit_ip, renewed)
        log.info("Anonymity confirmed. Exit IP: %s (host: %s)",
                  exit_ip, host_ip or "unknown")
        return identity
    except AnonymityError:
        raise  # Propagate fail-closed conditions untouched.
    except Exception as exc:
        # Any unexpected error in the safety layer is treated as a leak risk.
        raise AnonymityError(f"Anonymity verification failed unexpectedly: {exc}")
    finally:
        # Active cleanup and memory safety: always close the probe client.
        with contextlib.suppress(Exception):
            await client.aclose()
        log.info("Executing cleanup protocols for acquire_anonymous_identity.")