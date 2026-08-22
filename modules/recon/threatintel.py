"""
threatintel.py — External feed checks (personal notes).

Queries URLhaus and Google Safe Browsing (if keyed) to corroborate findings.
These are best-effort — no feed should abort the scan if down.

TODO:
- Consider adding more feeds (abuseIPDB?) if I need higher coverage.
"""

from __future__ import annotations

from typing import Any, List

from config import (
    GOOGLE_SAFE_BROWSING_API, GOOGLE_SAFE_BROWSING_KEY, URLHAUS_HOST_API,
)
from models import ThreatIntelHit
from modules.logging_setup import get_logger
from modules.proxy.tor_manager import build_client
from modules.util import host_of

log = get_logger("recon.threatintel")


def _urlhaus_hit_from_payload(data: dict, host: str) -> List[ThreatIntelHit]:
    """Turn a URLhaus 'ok' response into a hit."""
    status = str(data.get("query_status", ""))
    if status != "ok" or not (data.get("urls") or data.get("url_count")):
        return []

    count = data.get("url_count") or len(data.get("urls", []))
    return [ThreatIntelHit(
        source="URLhaus",
        listed=True,
        detail=f"Host listed on URLhaus with {count} malicious URL(s).",
        reference=str(data.get("urlhaus_reference", "https://urlhaus.abuse.ch/")),
    )]


async def _urlhaus(client: Any, host: str) -> List[ThreatIntelHit]:
    """Ask URLhaus about this host. Anything less than a clean answer = no hit."""
    try:
        resp = await client.post(URLHAUS_HOST_API, data={"host": host})
    except Exception as exc:
        log.info("URLhaus lookup failed (continuing): %s", exc)
        return []

    if resp.status_code != 200:
        return []
    return _urlhaus_hit_from_payload(resp.json(), host)


def _safe_browsing_payload(url: str) -> dict:
    """Request body Google wants — copy-pasted from their docs, don't touch it."""
    return {
        "client": {"clientId": "threat-recon", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                             "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }


def _safe_browsing_hit_from_matches(matches: list) -> List[ThreatIntelHit]:
    """Turn Google's 'matches' list into one summarized hit."""
    if not matches:
        return []
    kinds = ", ".join(sorted({m.get("threatType", "?") for m in matches}))
    return [ThreatIntelHit(
        source="Google Safe Browsing",
        listed=True,
        detail=f"Flagged by Google Safe Browsing: {kinds}.",
        reference="https://transparencyreport.google.com/safe-browsing/search",
    )]


async def _safe_browsing(client: Any, url: str) -> List[ThreatIntelHit]:
    """Query Google Safe Browsing v4 (skipped entirely if no API key is configured)."""
    if not GOOGLE_SAFE_BROWSING_KEY:
        return []

    try:
        resp = await client.post(GOOGLE_SAFE_BROWSING_API,
                                  params={"key": GOOGLE_SAFE_BROWSING_KEY},
                                  json=_safe_browsing_payload(url))
    except Exception as exc:
        log.info("Safe Browsing lookup failed (continuing): %s", exc)
        return []

    if resp.status_code != 200:
        return []
    return _safe_browsing_hit_from_matches(resp.json().get("matches") or [])


async def check_threat_intel(target_url: str, direct: bool = False) -> List[ThreatIntelHit]:
    """Corroborate the target against external feeds. Loopback yields nothing."""
    host = host_of(target_url)
    if not host or host == "localhost" or host.startswith("127."):
        log.info("%s is loopback, no feeds to check", host)
        return []

    client = build_client(direct=direct)
    findings: List[ThreatIntelHit] = []
    try:
        findings.extend(await _urlhaus(client, host))
        findings.extend(await _safe_browsing(client, target_url))
    except Exception as exc:
        # something outside the individual feed try/excepts went sideways
        log.error("Threat intel check error (continuing): %s", exc)
    finally:
        try:
            await client.aclose()
        except Exception as exc:
            log.debug("client.aclose() failed: %s", exc)
        listed = sum(1 for f in findings if f.listed)
        log.info("Threat intel done: %d feed hit(s).", listed)
    return findings