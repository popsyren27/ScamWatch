"""
cve.py — CVE lookups (notes).

Use the offline curated KB first, then enrich from NVD over Tor. Keep queries
slow and polite to avoid rate limits; curated entries take priority.

TODO:
- Expand the offline KB as I encounter repeat vulnerable versions.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional, Tuple

from config import (
    NVD_API_BASE,
    NVD_API_KEY,
    NVD_MAX_CVES_PER_PRODUCT,
)
from models import CveRecord, TechFingerprint
from modules.logging_setup import get_logger
from modules.proxy.tor_manager import build_client

log = get_logger("recon.cve")

# NVD's anonymous tier is roughly 5 req / 30s — this is the gap between calls.
_NVD_REQUEST_GAP_SECONDS: float = 1.0


# --------------------------------------------------------------------------
# Curated offline CVE knowledge base.
# --------------------------------------------------------------------------
# Small, high-confidence map of notorious vulnerable versions to their CVEs.
# Resilient floor for when NVD is rate-limited, unreachable over Tor, or slow.
# Merged with (and de-duplicated against) the live NVD lookup below.
#
# Each entry: product-substring, vulnerable-version prefixes, id, kind, severity,
# CVSS score, summary. ``kind`` is "cve" for a real CVE, "advisory" for a curated
# non-CVE finding (EOL/outdated) so a report never passes a pseudo-id off as a CVE.
_OFFLINE_CVES: Tuple[Dict[str, Any], ...] = (
    # --- Apache HTTP Server ---
    {"product": "apache", "versions": ("2.4.49",), "cve": "CVE-2021-41773",
     "kind": "cve", "severity": "HIGH", "score": 7.5,
     "summary": "Apache HTTP Server 2.4.49 path-traversal allowing source disclosure "
                "and, with mod_cgi, remote code execution via crafted '../' sequences."},
    {"product": "apache", "versions": ("2.4.49", "2.4.50"), "cve": "CVE-2021-42013",
     "kind": "cve", "severity": "CRITICAL", "score": 9.8,
     "summary": "Apache HTTP Server 2.4.49/2.4.50 path-traversal and RCE — an "
                "incomplete fix of CVE-2021-41773 left the bypass exploitable."},
    {"product": "apache", "versions": ("2.4.7", "2.4.17", "2.4.25", "2.4.29", "2.4.38",
                                       "2.4.41"), "cve": "ADVISORY-APACHE-OUTDATED",
     "kind": "advisory", "severity": "MEDIUM", "score": 5.3,
     "summary": "Apache httpd is several minor releases behind current — likely "
                "exposed to multiple patched CVEs; upgrade to the latest 2.4.x."},
    # --- nginx ---
    {"product": "nginx", "versions": ("1.16", "1.17", "1.18", "1.19", "1.20"),
     "cve": "CVE-2021-23017", "kind": "cve", "severity": "HIGH", "score": 7.7,
     "summary": "nginx resolver off-by-one heap write — a remote attacker controlling "
                "DNS responses can corrupt memory (potential RCE)."},
    # --- PHP ---
    {"product": "php", "versions": ("7.0", "7.1", "7.2", "7.3"), "cve": "CVE-2019-11043",
     "kind": "cve", "severity": "CRITICAL", "score": 9.8,
     "summary": "PHP-FPM remote code execution (env_path_info underflow) when fronted "
                "by certain nginx configurations."},
    {"product": "php", "versions": ("5.", "7.0", "7.1", "7.2", "7.3", "7.4"),
     "cve": "ADVISORY-PHP-EOL", "kind": "advisory", "severity": "HIGH", "score": 7.0,
     "summary": "PHP version is past end-of-life and no longer receives security "
                "patches — a standing, unpatched attack surface; migrate to 8.2+."},
    # --- TLS / crypto ---
    {"product": "openssl", "versions": ("1.0.1",), "cve": "CVE-2014-0160",
     "kind": "cve", "severity": "HIGH", "score": 7.5,
     "summary": "OpenSSL 'Heartbleed' — out-of-bounds read leaks server memory "
                "including private keys and session data."},
    {"product": "openssl", "versions": ("1.0.2", "1.1.0"), "cve": "ADVISORY-OPENSSL-EOL",
     "kind": "advisory", "severity": "MEDIUM", "score": 5.0,
     "summary": "OpenSSL branch is end-of-life and unpatched against newer TLS flaws."},
    # --- Java stack ---
    {"product": "log4j", "versions": ("2.0", "2.1", "2.2", "2.3", "2.4", "2.5",
                                       "2.6", "2.7", "2.8", "2.9", "2.10", "2.11",
                                       "2.12", "2.13", "2.14"),
     "cve": "CVE-2021-44228", "kind": "cve", "severity": "CRITICAL", "score": 10.0,
     "summary": "Apache Log4j 'Log4Shell' JNDI lookup remote code execution."},
    {"product": "spring", "versions": ("5.2", "5.3"), "cve": "CVE-2022-22965",
     "kind": "cve", "severity": "CRITICAL", "score": 9.8,
     "summary": "Spring Framework 'Spring4Shell' — data-binding RCE on JDK 9+ when "
                "deployed as a WAR on Tomcat."},
    # --- Front-end libraries (mapped from DOM asset versions) ---
    {"product": "jquery", "versions": ("1.", "2.", "3.0", "3.1", "3.2", "3.3", "3.4"),
     "cve": "CVE-2020-11023", "kind": "cve", "severity": "MEDIUM", "score": 6.1,
     "summary": "jQuery < 3.5.0 cross-site scripting via HTML containing <option> "
                "elements passed to DOM-manipulation methods."},
    {"product": "jquery", "versions": ("1.", "2.", "3.0", "3.1", "3.2", "3.3"),
     "cve": "CVE-2019-11358", "kind": "cve", "severity": "MEDIUM", "score": 6.1,
     "summary": "jQuery < 3.4.0 prototype pollution via $.extend with attacker-"
                "controlled JSON."},
    {"product": "bootstrap", "versions": ("3.", "4.0", "4.1", "4.2", "4.3"),
     "cve": "CVE-2019-8331", "kind": "cve", "severity": "MEDIUM", "score": 6.1,
     "summary": "Bootstrap < 3.4.1 / < 4.3.1 cross-site scripting in the tooltip / "
                "popover data-template attribute."},
    {"product": "angular", "versions": ("1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6"),
     "cve": "ADVISORY-ANGULARJS-EOL", "kind": "advisory", "severity": "MEDIUM",
     "score": 6.0,
     "summary": "AngularJS (1.x) is end-of-life with known, unpatched XSS/sandbox-"
                "escape issues; migrate to a supported framework."},
    {"product": "lodash", "versions": ("1.", "2.", "3.", "4.0", "4.1", "4.2", "4.3",
                                        "4.4", "4.5", "4.6", "4.7", "4.8", "4.9",
                                        "4.10", "4.11", "4.12", "4.13", "4.14",
                                        "4.15", "4.16"),
     "cve": "CVE-2019-10744", "kind": "cve", "severity": "HIGH", "score": 7.4,
     "summary": "lodash < 4.17.12 prototype pollution via defaultsDeep."},
    {"product": "moment", "versions": ("2.0", "2.1", "2.2", "2.10", "2.11", "2.12",
                                        "2.13", "2.14", "2.15", "2.16", "2.17", "2.18",
                                        "2.19", "2.20", "2.21", "2.22", "2.23", "2.24",
                                        "2.25", "2.26", "2.27", "2.28", "2.29.0",
                                        "2.29.1"),
     "cve": "CVE-2022-31129", "kind": "cve", "severity": "HIGH", "score": 7.5,
     "summary": "moment.js < 2.29.4 regular-expression denial of service (ReDoS)."},
    # --- CMS ---
    {"product": "wordpress", "versions": ("4.", "5.0", "5.1", "5.2", "5.3", "5.4"),
     "cve": "ADVISORY-WORDPRESS-OUTDATED", "kind": "advisory", "severity": "MEDIUM",
     "score": 5.3,
     "summary": "Outdated WordPress core (< 5.5) — exposed to multiple disclosed "
                "core/plugin vulnerabilities; update and audit installed plugins."},
    {"product": "drupal", "versions": ("7.", "8.0", "8.1", "8.2", "8.3", "8.4", "8.5"),
     "cve": "CVE-2018-7600", "kind": "cve", "severity": "CRITICAL", "score": 9.8,
     "summary": "Drupal 'Drupalgeddon2' — unauthenticated remote code execution via "
                "form-API render arrays."},
)


def _offline_lookup(fp: TechFingerprint) -> List[CveRecord]:
    """Return curated CVEs whose product/version prefix matches a fingerprint."""
    if not fp.version:
        return []

    matches: List[CveRecord] = []
    for entry in _OFFLINE_CVES:
        if entry["product"] not in fp.product.lower():
            continue
        if not any(fp.version.startswith(prefix) for prefix in entry["versions"]):
            continue
        matches.append(CveRecord(
            cve_id=str(entry["cve"]),
            severity=str(entry["severity"]),
            score=float(entry["score"]),
            summary=str(entry["summary"]),
            matched_product=f"{fp.product} {fp.version}",
            kind=str(entry.get("kind", "cve")),
        ))
    return matches


def _as_float(value: Any) -> Optional[float]:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _severity_of(cve: Dict[str, Any]) -> Tuple[str, Optional[float]]:
    """Extract a (severity, score) pair, preferring CVSS v3.1 > v3.0 > v2."""
    metrics: Dict[str, Any] = cve.get("metrics", {}) or {}
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            severity = str(data.get("baseSeverity", "UNKNOWN"))
            score = _as_float(data.get("baseScore"))
            return severity, score

    v2 = metrics.get("cvssMetricV2") or []
    if v2:
        data = v2[0].get("cvssData", {})
        severity = str(v2[0].get("baseSeverity", "UNKNOWN"))
        score = _as_float(data.get("baseScore"))
        return severity, score

    return "UNKNOWN", None


def _summary_of(cve: Dict[str, Any]) -> str:
    for desc in cve.get("descriptions", []) or []:
        if desc.get("lang") == "en":
            return str(desc.get("value", ""))[:400]
    return ""


async def _fetch_nvd_payload(client: Any, term: str) -> Optional[Dict[str, Any]]:
    """Hit the NVD endpoint for one search term. None on anything less than a clean 200."""
    params = {"keywordSearch": term, "resultsPerPage": NVD_MAX_CVES_PER_PRODUCT}
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    try:
        resp = await client.get(NVD_API_BASE, params=params, headers=headers)
    except Exception as exc:
        log.warning("NVD query failed for '%s' (continuing): %s", term, exc)
        return None

    if resp.status_code == 403:
        log.warning("NVD rate-limited (403) for '%s' — backing off.", term)
        return None
    if resp.status_code != 200:
        log.warning("NVD returned %s for '%s'.", resp.status_code, term)
        return None
    return resp.json()


def _records_from_nvd_payload(payload: Dict[str, Any], term: str) -> List[CveRecord]:
    """Turn a raw NVD JSON blob into our CveRecord shape, skipping half-broken entries."""
    records: List[CveRecord] = []
    for item in payload.get("vulnerabilities", []) or []:
        cve: Dict[str, Any] = item.get("cve", {}) or {}
        cve_id = cve.get("id")
        if not cve_id:
            continue
        severity, score = _severity_of(cve)
        try:
            record = CveRecord(
                cve_id=str(cve_id),
                severity=severity,
                score=score,
                summary=_summary_of(cve),
                matched_product=term,
                kind="cve",
            )
        except Exception as exc:
            # NVD's schema has drifted before — one bad record shouldn't sink the batch
            log.debug("Skipping malformed NVD record %s: %s", cve_id, exc)
            continue
        records.append(record)
    return records


async def _query_one(client: Any, fp: TechFingerprint) -> List[CveRecord]:
    """Query the NVD for a single fingerprint. Returns [] on any failure — always."""
    term = fp.product if not fp.version else f"{fp.product} {fp.version}"
    payload = await _fetch_nvd_payload(client, term)
    if payload is None:
        return []
    return _records_from_nvd_payload(payload, term)


async def _run_live_lookups(targets: List[TechFingerprint], direct: bool) -> List[CveRecord]:
    """Sweep live NVD for every target, politely, one at a time, over Tor (or direct)."""
    records: List[CveRecord] = []
    client = build_client(direct=direct)
    try:
        for fp in targets:
            records.extend(await _query_one(client, fp))
            await asyncio.sleep(_NVD_REQUEST_GAP_SECONDS)
    except Exception as exc:
        # offline KB already has records in hand — a live-side hiccup isn't fatal
        log.error("CVE cross-reference error (continuing): %s", exc)
    finally:
        try:
            await client.aclose()
        except Exception as exc:
            log.debug("client.aclose() failed: %s", exc)
    return records


def _dedupe_keep_first(records: List[CveRecord]) -> List[CveRecord]:
    """Drop repeat CVE ids, keeping the first hit (curated entries go in first, so they win)."""
    deduped: List[CveRecord] = []
    seen: set = set()
    for rec in records:
        if rec.cve_id in seen:
            continue
        seen.add(rec.cve_id)
        deduped.append(rec)
    return deduped


async def cross_reference_cves(fingerprints: List[TechFingerprint],
                                direct: bool = False) -> List[CveRecord]:
    """Look up CVEs for every versioned fingerprint.

    Only fingerprints WITH a version are queried — a bare product name yields
    too much noise to be useful as evidence. ``direct`` only affects which
    client reaches NVD (loopback testing); the lookup target is always NVD.
    """
    targets = [fp for fp in fingerprints if fp.version]
    if not targets:
        log.info("No versioned components to cross-reference.")
        return []

    # offline KB first — instant and network-free, so a famously-vulnerable
    # stack still gets reported even if NVD is unreachable
    offline_records: List[CveRecord] = []
    for fp in targets:
        offline_records.extend(_offline_lookup(fp))

    live_records = await _run_live_lookups(targets, direct)

    # curated entries listed first so they win the de-dupe
    deduped = _dedupe_keep_first(offline_records + live_records)
    log.info("CVE cross-reference complete: %d record(s) (offline+NVD, deduped).", len(deduped))
    return deduped