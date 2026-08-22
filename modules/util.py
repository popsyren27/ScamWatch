"""
util.py — Tiny, dependency-free helpers for quick reuse.

Keep these pure and small so imports don't drag in heavy deps.

TODO:
- Maybe add better URL normalization for edge-case schemes if needed.
- Consider returning Result types instead of silent defaults.
- Add unit tests for weird URL edge cases.
"""

import ipaddress
from urllib.parse import urlparse


def host_of(url: str) -> str:
    """Lowercased hostname of a URL, tolerating bare-host inputs ('example.com')."""
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        return (parsed.hostname or "").lower()
    except Exception:
        # broad catch is intentional — caller tolerates an empty host on parse failure
        return ""


def is_loopback(url: str) -> bool:
    """True if the target resolves to the local machine (127.0.0.0/8, ::1, localhost).

    Used to gate the 'direct' (no-Tor) scan mode: bypassing Tor is permitted ONLY
    for loopback targets (testing the local decoy), never for a real remote site —
    so the anonymity guarantee can never be silently disabled against a live scam.
    """
    host = host_of(url)
    if host in ("localhost", "ip6-localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def normalize_url(raw: str) -> str:
    """Trim and default a bare host to https:// so operators can paste loosely."""
    cleaned = (raw or "").strip()
    if cleaned and not cleaned.lower().startswith(("http://", "https://")):
        cleaned = "https://" + cleaned
    return cleaned