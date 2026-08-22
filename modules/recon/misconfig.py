"""
misconfig.py — Sensitive-path probes (notes).

Probes configured sensitive paths but reads only status/Content-Length — never
downloads bodies. Has a soft-404 catch-all guard to avoid noise on sites that
reply 200 everywhere.

TODO:
- Expand probe set if I notice common admin paths missing from MISCONFIG_PATHS.
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional, Tuple
from urllib.parse import urljoin, urlparse

from pydantic import StrictStr, validate_call

from config import CATCHALL_PROBE_PATHS, MISCONFIG_META, MISCONFIG_PATHS
from models import MisconfigFinding
from modules.logging_setup import get_logger
from modules.proxy.tor_manager import build_client

log = get_logger("recon.misconfig")

# Content-Length within this many bytes of the catch-all baseline is treated as
# "the same catch-all page" rather than a distinct exposed file.
_BASELINE_TOLERANCE: int = 24


def _origin(url: str) -> str:
    """Turn any URL into scheme://host/ so there's one clean base to probe against."""
    parts = urlparse(url)
    scheme = parts.scheme or "https"
    netloc = parts.netloc or parts.path  # in case someone passes a bare host
    return f"{scheme}://{netloc}/"


def _content_length(resp: Any) -> Optional[int]:
    """Read Content-Length off the headers. Never touches the actual body."""
    raw = resp.headers.get("content-length")
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


async def _probe_one_catchall_path(client: Any, base: str, probe: str) -> Optional[Tuple[bool, int]]:
    """Hit one decoy path, see if the site lies and says 200 to everything."""
    full = urljoin(base, probe.lstrip("/"))
    try:
        resp = await client.get(full)
    except Exception as exc:
        log.info("Baseline probe %s inconclusive: %s", full, exc)
        return None

    if resp.status_code != 200:
        return None

    length = len(resp.content or b"")
    log.warning("Host is a CATCH-ALL (200 on nonexistent %s, %dB) — "
                "misconfig results will be size-validated.", probe, length)
    return True, length


async def _baseline(client: Any, base: str) -> Tuple[bool, Optional[int]]:
    """Figure out if this host fake-200s everything, and if so, how big that page is.

    We DO read these bodies (only these — never the target's real sensitive
    files) purely to measure the size of the catch-all page.
    """
    for probe in CATCHALL_PROBE_PATHS:
        result = await _probe_one_catchall_path(client, base, probe)
        if result is not None:
            return result
    return False, None


def _is_indistinguishable_from_catchall(clen: Optional[int], baseline_len: Optional[int]) -> bool:
    """Is this 200 just the same fake catch-all page again, or an actual file?"""
    if clen is None or baseline_len is None:
        return True  # can't prove it's different, so don't trust it
    return abs(clen - baseline_len) <= _BASELINE_TOLERANCE


async def _fetch_status(client: Any, full: str) -> Any:
    """HEAD first (cheap), fall back to GET only if the server refuses HEAD."""
    resp = await client.head(full)
    if resp.status_code in (405, 501):
        resp = await client.get(full)
    return resp


async def _probe(client: Any, base: str, path: str, catchall: bool,
                  baseline_len: Optional[int]) -> MisconfigFinding:
    """Check one sensitive path. This function refuses to throw — worst case, 'not exposed'."""
    full = urljoin(base, path.lstrip("/"))
    category, severity = MISCONFIG_META.get(path, ("", "info"))

    try:
        resp = await _fetch_status(client, full)
    except Exception as exc:
        log.info("Probe inconclusive for %s (treated as not exposed): %s", full, exc)
        return MisconfigFinding(path=path, http_status=0, exposed=False,
                                 category=category, severity="info")

    status = resp.status_code
    exposed = status == 200

    if exposed and catchall:
        clen = _content_length(resp)
        if _is_indistinguishable_from_catchall(clen, baseline_len):
            log.info("Suppressed catch-all false positive: %s (200 but "
                      "indistinguishable from soft-404).", full)
            return MisconfigFinding(path=path, http_status=int(status), exposed=False,
                                     category=category, severity="info")

    if exposed:
        log.warning("EXPOSED [%s/%s]: %s responded 200 OK.", category, severity, full)

    return MisconfigFinding(path=path, http_status=int(status), exposed=exposed,
                             category=category, severity=severity if exposed else "info")


async def _run_all_probes(client: Any, base: str, catchall: bool,
                           baseline_len: Optional[int]) -> list[MisconfigFinding]:
    """Fire every configured path probe at once, and drop any that blow up."""
    raw_results = await asyncio.gather(
        *[_probe(client, base, p, catchall, baseline_len) for p in MISCONFIG_PATHS],
        return_exceptions=True,
    )
    findings: list[MisconfigFinding] = []
    for result in raw_results:
        if isinstance(result, MisconfigFinding):
            findings.append(result)
        else:
            log.warning("A misconfig probe errored out: %s", result)
    return findings


@validate_call
async def check_misconfigurations(target_url: StrictStr,
                                   direct: bool = False) -> list[MisconfigFinding]:
    """Probe the configured sensitive paths against the target's origin.

    ``direct=True`` (loopback testing only) bypasses Tor so the local decoy is
    reachable; for any remote target this stays Tor-routed.
    """
    base = _origin(target_url)
    client = build_client(direct=direct)
    findings: list[MisconfigFinding] = []
    try:
        # baseline first, always — probing without it means trusting a liar host
        catchall, baseline_len = await _baseline(client, base)
        findings = await _run_all_probes(client, base, catchall, baseline_len)
    except Exception as exc:
        log.error("Misconfiguration sweep error (continuing): %s", exc)
    finally:
        try:
            await client.aclose()
        except Exception as exc:
            log.debug("client.aclose() failed: %s", exc)
        exposed_count = sum(1 for f in findings if f.exposed)
        log.info("Misconfig sweep done: %d exposed of %d probed.", exposed_count, len(findings))
    return findings