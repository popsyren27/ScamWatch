"""
intel.py — Domain & hosting intelligence (short dev notes).

RDAP, crt.sh and favicon checks to find registrar, hosting provider, age and
related domains. Parsing helpers are kept separate so I can unit-test them
offline.

TODO:
- Add caching for crt.sh responses if I run lots of lookups during testing.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from config import (
    CRT_SH_BASE, CRT_SH_MAX_RELATED, RDAP_DOMAIN_BASE, RDAP_IP_BASE,
)
from models import DomainIntel
from modules.logging_setup import get_logger
from modules.proxy.tor_manager import build_client
from modules.util import host_of

log = get_logger("recon.intel")

# Common multi-label public suffixes so 'shop.scam.com.ph' -> 'scam.com.ph'.
_MULTI_SUFFIXES = (
    "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph", "co.uk", "org.uk",
    "com.au", "co.jp", "com.sg", "com.my", "co.id",
)


def registrable_domain(host: str) -> str:
    """Best-effort registrable domain (no public-suffix-list dependency)."""
    host = (host or "").lower().strip(".")
    if not host or host.replace(".", "").isdigit():
        return host  # raw IP
    labels = host.split(".")
    for suf in _MULTI_SUFFIXES:
        if host.endswith("." + suf) or host == suf:
            parts = suf.split(".")
            return ".".join(labels[-(len(parts) + 1):])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _vcard_field(entity: Dict[str, Any], field: str) -> Optional[str]:
    """Grab one value (like email) out of an RDAP entity's vcard blob."""
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2:
        return None
    for row in vcard[1]:
        if isinstance(row, list) and len(row) >= 4 and row[0] == field:
            return str(row[3])
    return None


def _find_abuse_email(entities: List[Dict[str, Any]]) -> Optional[str]:
    """Dig through RDAP entities (and nested ones) for an abuse contact."""
    for ent in entities or []:
        roles = [str(r).lower() for r in ent.get("roles", [])]
        if "abuse" in roles:
            email = _vcard_field(ent, "email")
            if email:
                return email
        nested = ent.get("entities")
        if nested:
            found = _find_abuse_email(nested)
            if found:
                return found
    return None


def _domain_creation_date(events: List[Dict[str, Any]]) -> Optional[str]:
    """Find the domain's registration date in an RDAP events list."""
    for ev in events or []:
        if str(ev.get("eventAction", "")).lower() in ("registration", "created"):
            return ev.get("eventDate")
    return None


def _registrar_info(entities: List[Dict[str, Any]]) -> tuple[Optional[str], Optional[str]]:
    """Pull the registrar's name and abuse email out of the entities list."""
    registrar: Optional[str] = None
    abuse_email: Optional[str] = None
    for ent in entities or []:
        roles = [str(r).lower() for r in ent.get("roles", [])]
        if "registrar" in roles:
            registrar = _vcard_field(ent, "fn") or registrar
            abuse_email = _find_abuse_email([ent])
    if not abuse_email:
        abuse_email = _find_abuse_email(entities)
    return registrar, abuse_email


def _nameservers_of(data: Dict[str, Any]) -> List[str]:
    """List the RDAP-reported nameservers, lowercased."""
    names: List[str] = []
    for ns in data.get("nameservers", []) or []:
        name = ns.get("ldhName") if isinstance(ns, dict) else None
        if name:
            names.append(str(name).lower())
    return names


def parse_domain_rdap(data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract registrar / abuse / creation-date / nameservers from RDAP JSON."""
    registrar, abuse_email = _registrar_info(data.get("entities", []) or [])
    return {
        "registrar": registrar,
        "registrar_abuse_email": abuse_email,
        "creation_date": _domain_creation_date(data.get("events", []) or []),
        "nameservers": _nameservers_of(data),
    }


def _asn_of(data: Dict[str, Any]) -> Optional[str]:
    """ASN sometimes hides in arin-style fields — best-effort scavenging."""
    for key in ("arin_originas0_originautnumbers", "originAutnums"):
        value = data.get(key)
        if value:
            return f"AS{value[0]}" if isinstance(value, list) else str(value)
    return None


def parse_ip_rdap(data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract hosting provider / abuse email / ASN from IP-RDAP JSON."""
    return {
        "hosting_provider": data.get("name"),
        "hosting_abuse_email": _find_abuse_email(data.get("entities", []) or []),
        "asn": _asn_of(data),
    }


def _try_parse_date(raw: str) -> Optional[_dt.datetime]:
    """Try a couple of date formats until one parses."""
    parsers = (
        lambda s: _dt.datetime.fromisoformat(s),
        lambda s: _dt.datetime.strptime(s[:10], "%Y-%m-%d"),
    )
    for parse in parsers:
        try:
            return parse(raw)
        except (ValueError, TypeError):
            continue
    return None


def age_days(creation_date: Optional[str], now: Optional[_dt.datetime] = None) -> Optional[int]:
    """Whole days since a registration date (ISO-8601), or None if we can't tell."""
    if not creation_date:
        return None
    now = now or _dt.datetime.now(_dt.timezone.utc)
    raw = str(creation_date).strip().replace("Z", "+00:00")
    parsed = _try_parse_date(raw)
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return max(0, (now - parsed).days)


async def _favicon_hash(client: Any, base: str) -> Optional[str]:
    """SHA-256 of /favicon.ico — same icon on two sites hints they're related."""
    try:
        resp = await client.get(urljoin(base, "favicon.ico"))
        if resp.status_code == 200 and resp.content:
            return hashlib.sha256(resp.content).hexdigest()[:32]
    except Exception as exc:
        log.info("Favicon fetch failed: %s", exc)
    return None


async def _discover_campaign(client: Any, domain: str) -> List[str]:
    """Sibling domains sharing a TLS cert, found via Certificate Transparency logs."""
    related: List[str] = []
    try:
        resp = await client.get(CRT_SH_BASE, params={"q": domain, "output": "json"})
        if resp.status_code != 200:
            return related
        seen = {domain}
        for entry in resp.json():
            for name in str(entry.get("name_value", "")).splitlines():
                name = name.strip().lstrip("*.").lower()
                if name and name not in seen and domain not in name:
                    seen.add(name)
                    related.append(name)
            if len(related) >= CRT_SH_MAX_RELATED:
                break
    except Exception as exc:
        # crt.sh is flaky often enough that this isn't worth failing the scan over
        log.info("crt.sh campaign lookup failed: %s", exc)
    return related[:CRT_SH_MAX_RELATED]


async def _apply_domain_rdap(client: Any, domain: str, intel: DomainIntel) -> None:
    """Fetch domain RDAP and stuff the results into intel. Failures become notes, not crashes."""
    try:
        resp = await client.get(urljoin(RDAP_DOMAIN_BASE, domain))
        if resp.status_code != 200:
            intel.notes.append(f"RDAP returned HTTP {resp.status_code} for the domain.")
            return
        parsed = parse_domain_rdap(resp.json())
        intel.registrar = parsed["registrar"]
        intel.registrar_abuse_email = parsed["registrar_abuse_email"]
        intel.creation_date = parsed["creation_date"]
        intel.age_days = age_days(parsed["creation_date"])
        intel.nameservers = parsed["nameservers"][:6]
    except Exception as exc:
        intel.notes.append(f"Domain RDAP lookup failed: {exc}")


async def _apply_hosting_rdap(client: Any, exit_ip: Optional[str], intel: DomainIntel) -> None:
    """Fetch hosting RDAP by exit IP, if we actually have a usable IP to ask about."""
    if not exit_ip or exit_ip.startswith(("direct", "unknown", "local")):
        return
    try:
        resp = await client.get(urljoin(RDAP_IP_BASE, exit_ip))
        if resp.status_code == 200:
            ip_meta = parse_ip_rdap(resp.json())
            intel.hosting_provider = ip_meta["hosting_provider"]
            intel.hosting_abuse_email = ip_meta["hosting_abuse_email"]
            intel.asn = ip_meta["asn"]
    except Exception as exc:
        log.info("Hosting RDAP lookup failed for %s: %s", exit_ip, exc)


async def _apply_favicon_and_campaign(client: Any, target_url: str, host: str,
                                       domain: str, intel: DomainIntel) -> None:
    """Grab the favicon hash and any sibling domains, stash both on intel."""
    base = f"{urlparse(target_url).scheme or 'https'}://{host}/"
    intel.favicon_hash = await _favicon_hash(client, base)
    intel.related_domains = await _discover_campaign(client, domain)


async def gather_intel(target_url: str, exit_ip: Optional[str] = None,
                        direct: bool = False) -> DomainIntel:
    """Collect registration + hosting + campaign intelligence for a target.

    Loopback targets get a minimal stub (no public registration exists).
    """
    host = host_of(target_url)
    domain = registrable_domain(host)
    intel = DomainIntel(domain=domain)

    if not domain or domain.replace(".", "").isdigit():
        intel.notes.append("No registrable domain (raw IP/loopback) — registration "
                            "intelligence not applicable.")
        return intel

    client = build_client(direct=direct)
    try:
        await _apply_domain_rdap(client, domain, intel)
        await _apply_hosting_rdap(client, exit_ip, intel)
        await _apply_favicon_and_campaign(client, target_url, host, domain, intel)
    finally:
        try:
            await client.aclose()
        except Exception as exc:
            log.debug("client.aclose() failed: %s", exc)
        log.info("Intel for %s: age=%s, registrar=%s, %d sibling domain(s).",
                  domain, intel.age_days, intel.registrar, len(intel.related_domains))
    return intel