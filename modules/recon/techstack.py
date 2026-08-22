"""
techstack.py — Passive tech fingerprinting.

Scan headers, cookies and DOM artifacts to guess software/components and
versions. Used later for CVE lookups. All signatures live in
knowledge/tech_signatures.json — edit the JSON to tune detection.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from models import IngestedPage, TechFingerprint
from modules.logging_setup import get_logger
from modules.recon import knowledge_loader as kb

log = get_logger("recon.techstack")

# product/version extractor, e.g. "nginx/1.14.0" or "PHP/7.2.1".
_PRODUCT_VERSION = re.compile(
    r"([A-Za-z][A-Za-z0-9_\-]+)[/ ]v?(\d+(?:\.\d+){0,3})"
)


def _lower_header_map(headers: Dict[str, str]) -> Dict[str, str]:
    return {k.lower(): v for k, v in (headers or {}).items()}


def _versionless_token(raw: str) -> Optional[str]:
    stripped = raw.strip()
    before_delimiter = stripped.split(";")[0].split(",")[0]
    token = before_delimiter.strip()
    if token and re.match(r"^[A-Za-z][\w\-.]*$", token):
        return token
    return None


def _parse_token(raw: str, source: str, rule_id: str) -> List[TechFingerprint]:
    found = [
        TechFingerprint(product=product, version=version, source=source, rule_id=rule_id)
        for product, version in _PRODUCT_VERSION.findall(raw)
    ]
    if found:
        return found

    fallback = _versionless_token(raw) if raw.strip() else None
    if fallback:
        return [TechFingerprint(product=fallback, version=None, source=source, rule_id=rule_id)]

    return []


def _from_headers(headers: Dict[str, str]) -> List[TechFingerprint]:
    lower = _lower_header_map(headers)
    out: List[TechFingerprint] = []
    for rule_id, name in kb.load_revealing_headers():
        value = lower.get(name)
        if not value:
            continue
        out.extend(_parse_token(value, f"header:{name}", rule_id))
    return out


def _meta_generator_fingerprint(content: str, name: str) -> List[TechFingerprint]:
    parsed = _parse_token(content, f"meta:{name}", "tech.meta-generator")
    if parsed:
        return parsed
    if not content.strip():
        return []
    match = re.match(r"([A-Za-z][\w\-. ]+?)\s+(\d+(?:\.\d+)+)", content.strip())
    if match:
        return [TechFingerprint(product=match.group(1).strip(), version=match.group(2),
                                source=f"meta:{name}", rule_id="tech.meta-generator")]
    return [TechFingerprint(product=content.strip()[:60], version=None,
                            source=f"meta:{name}", rule_id="tech.meta-generator")]


def _from_dom(dom_html: str) -> List[TechFingerprint]:
    if not dom_html:
        return []
    out: List[TechFingerprint] = []
    try:
        from bs4 import BeautifulSoup  # type: ignore

        soup = BeautifulSoup(dom_html, "html.parser")
        for meta in soup.find_all("meta"):
            name = (meta.get("name") or meta.get("property") or "").lower()
            content = meta.get("content") or ""
            if name in {"generator", "application-name"} and content:
                out.extend(_meta_generator_fingerprint(content, name))
    except Exception as exc:
        log.warning("DOM tech parse failed (continuing): %s", exc)
    return out


def _from_cookies(headers: Dict[str, str]) -> List[TechFingerprint]:
    lower = _lower_header_map(headers)
    blob = lower.get("set-cookie", "").lower()
    if not blob:
        return []
    out: List[TechFingerprint] = []
    for rule_id, needle, product in kb.load_cookie_signatures():
        if needle in blob:
            out.append(TechFingerprint(product=product, version=None,
                                       source=f"cookie:{needle}", rule_id=rule_id))
    return out


def _from_dom_signatures(dom_html: str) -> List[TechFingerprint]:
    if not dom_html:
        return []
    out: List[TechFingerprint] = []
    for rule_id, product, pattern in kb.load_dom_signatures():
        if pattern.search(dom_html):
            out.append(TechFingerprint(product=product, version=None,
                                       source="dom:path", rule_id=rule_id))
    for rule_id, products, pattern in kb.load_js_lib_patterns():
        for lib, version in pattern.findall(dom_html):
            lib_l = lib.lower()
            matched = next((p for p in products if p.startswith(lib_l)), lib_l)
            out.append(TechFingerprint(product=matched, version=version,
                                       source="dom:asset", rule_id=rule_id))
    return out


def _dedupe(items: List[TechFingerprint]) -> List[TechFingerprint]:
    seen: set = set()
    unique: List[TechFingerprint] = []
    for item in items:
        key = (item.product.lower(), item.version or "")
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def _format_for_log(fingerprints: List[TechFingerprint]) -> str:
    parts = []
    for f in fingerprints:
        label = f.product
        if f.version:
            label += f"/{f.version}"
        parts.append(label)
    return ", ".join(parts) or "none identified"


def map_tech_stack(page: IngestedPage) -> List[TechFingerprint]:
    fingerprints: List[TechFingerprint] = []
    try:
        fingerprints.extend(_from_headers(page.response_headers))
        fingerprints.extend(_from_cookies(page.response_headers))
        fingerprints.extend(_from_dom(page.dom_html))
        fingerprints.extend(_from_dom_signatures(page.dom_html))
    except Exception as exc:
        log.error("Tech-stack mapping error (continuing): %s", exc)
    result = _dedupe(fingerprints)
    log.info("Tech stack: %s", _format_for_log(result))
    return result
