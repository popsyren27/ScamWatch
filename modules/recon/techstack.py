"""
techstack.py — Passive tech fingerprinting (notes).

Scan headers, cookies and DOM artifacts to guess software/components and
versions. Used later for CVE lookups.

TODO:
- Add heuristics for newer JS frameworks if I see gaps in detection.
"""

# fingerprinting is more vibes than science. if this starts guessing wrong,
# it's probably one of these regexes being too greedy. check there first.

from __future__ import annotations

import re
from typing import Dict, Final, List, Optional, Pattern, Tuple

from models import IngestedPage, TechFingerprint
from modules.logging_setup import get_logger

log = get_logger("recon.techstack")

# Headers that frequently disclose product + version.
_REVEALING_HEADERS: Final[Tuple[str, ...]] = (
    "server",
    "x-powered-by",
    "x-generator",
    "x-aspnet-version",
    "x-drupal-cache",
    "via",
)

# product/version extractor, e.g. "nginx/1.14.0" or "PHP/7.2.1".
_PRODUCT_VERSION: Final[Pattern[str]] = re.compile(
    r"([A-Za-z][A-Za-z0-9_\-]+)[/ ]v?(\d+(?:\.\d+){0,3})"
)

# Cookie name (lowercased substring) -> product it implies. Session-cookie
# naming is a reliable, passive backend fingerprint.
_COOKIE_SIGNATURES: Final[Tuple[Tuple[str, str], ...]] = (
    ("wordpress_logged_in", "WordPress"),
    ("wp-settings", "WordPress"),
    ("woocommerce", "WooCommerce"),
    ("phpsessid", "PHP"),
    ("jsessionid", "Java"),
    ("asp.net_sessionid", "ASP.NET"),
    ("aspsessionid", "ASP"),
    ("laravel_session", "Laravel"),
    ("xsrf-token", "Laravel"),
    ("ci_session", "CodeIgniter"),
    ("csrftoken", "Django"),
    ("sessionid", "Django"),
    ("_shopify", "Shopify"),
    ("cfduid", "Cloudflare"),
    ("__cf_bm", "Cloudflare"),
)

# DOM/asset-path signatures -> (product, regex). Detects CMS/framework even when
# the server hides its headers, by reading paths the rendered page references.
_DOM_SIGNATURES: Final[Tuple[Tuple[str, Pattern[str]], ...]] = (
    ("WordPress", re.compile(r"/wp-(?:content|includes)/", re.I)),
    ("Drupal", re.compile(r"/sites/(?:all|default)/|drupal-settings-json", re.I)),
    ("Joomla", re.compile(r"/media/jui/|/templates/[^/]+/joomla|joomla!", re.I)),
    ("Magento", re.compile(r"/static/version\d|/mage/|magento", re.I)),
    ("Shopify", re.compile(r"cdn\.shopify\.com|shopify\.theme", re.I)),
    ("Wix", re.compile(r"static\.wixstatic\.com|wix\.com", re.I)),
    ("Squarespace", re.compile(r"squarespace", re.I)),
    ("Next.js", re.compile(r"/_next/static/", re.I)),
    ("React", re.compile(r"data-reactroot|/react(?:\.production)?\.min\.js", re.I)),
    ("Vue.js", re.compile(r"data-v-[0-9a-f]{8}|vue(?:\.runtime)?\.min\.js", re.I)),
)

# Versioned front-end libraries embedded in script/link filenames, e.g.
# "jquery-3.4.1.min.js" or "bootstrap.4.5.0.css". These map to real CVEs.
_JS_LIB_VERSION: Final[Pattern[str]] = re.compile(
    r"\b(jquery|bootstrap|angular(?:js)?|vue|react|lodash|moment)"
    r"[-./ ]v?(\d+(?:\.\d+){1,3})", re.I)


def _lower_header_map(headers: Dict[str, str]) -> Dict[str, str]:
    """Headers arrive with random casing, this just flattens that once."""
    return {k.lower(): v for k, v in (headers or {}).items()}


def _versionless_token(raw: str) -> Optional[str]:
    """If there's no version number, see if there's at least a clean product name."""
    stripped = raw.strip()
    before_delimiter = stripped.split(";")[0].split(",")[0]
    token = before_delimiter.strip()
    if token and re.match(r"^[A-Za-z][\w\-.]*$", token):
        return token
    return None


def _parse_token(raw: str, source: str) -> List[TechFingerprint]:
    """Pull every product[/version] token out of one header/meta string."""
    found = [
        TechFingerprint(product=product, version=version, source=source)
        for product, version in _PRODUCT_VERSION.findall(raw)
    ]
    if found:
        return found

    fallback = _versionless_token(raw) if raw.strip() else None
    if fallback:
        return [TechFingerprint(product=fallback, version=None, source=source)]

    return []


def _from_headers(headers: Dict[str, str]) -> List[TechFingerprint]:
    """Check the handful of headers that like to blab about server software."""
    lower = _lower_header_map(headers)
    out: List[TechFingerprint] = []
    for name in _REVEALING_HEADERS:
        value = lower.get(name)
        if not value:
            continue
        out.extend(_parse_token(value, f"header:{name}"))
    return out


def _meta_generator_fingerprint(content: str, name: str) -> List[TechFingerprint]:
    """Handle a <meta name='generator' content='WordPress 5.2'>-style tag."""
    parsed = _parse_token(content, f"meta:{name}")
    if parsed:
        return parsed
    if not content.strip():
        return []
    match = re.match(r"([A-Za-z][\w\-. ]+?)\s+(\d+(?:\.\d+)+)", content.strip())
    if match:
        return [TechFingerprint(product=match.group(1).strip(), version=match.group(2),
                                 source=f"meta:{name}")]
    return [TechFingerprint(product=content.strip()[:60], version=None, source=f"meta:{name}")]


def _from_dom(dom_html: str) -> List[TechFingerprint]:
    """Look at <meta generator> tags for a product name, if the DOM even loaded."""
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
    """Infer backend products from Set-Cookie names (passive fingerprint)."""
    lower = _lower_header_map(headers)
    blob = lower.get("set-cookie", "").lower()
    if not blob:
        return []
    out: List[TechFingerprint] = []
    for needle, product in _COOKIE_SIGNATURES:
        if needle in blob:
            out.append(TechFingerprint(product=product, version=None, source=f"cookie:{needle}"))
    return out


def _from_dom_signatures(dom_html: str) -> List[TechFingerprint]:
    """Detect CMS/frameworks and versioned JS libs from DOM asset paths."""
    if not dom_html:
        return []
    out: List[TechFingerprint] = []
    for product, pattern in _DOM_SIGNATURES:
        if pattern.search(dom_html):
            out.append(TechFingerprint(product=product, version=None, source="dom:path"))
    for lib, version in _JS_LIB_VERSION.findall(dom_html):
        out.append(TechFingerprint(product=lib.lower(), version=version, source="dom:asset"))
    return out


def _dedupe(items: List[TechFingerprint]) -> List[TechFingerprint]:
    """Same product+version showing up five times from five sources is one entry."""
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
    """Turn the final list into one readable line for the summary log."""
    parts = []
    for f in fingerprints:
        label = f.product
        if f.version:
            label += f"/{f.version}"
        parts.append(label)
    return ", ".join(parts) or "none identified"


def map_tech_stack(page: IngestedPage) -> List[TechFingerprint]:
    """Return the de-duplicated set of identified software components."""
    fingerprints: List[TechFingerprint] = []
    try:
        fingerprints.extend(_from_headers(page.response_headers))
        fingerprints.extend(_from_cookies(page.response_headers))
        fingerprints.extend(_from_dom(page.dom_html))
        fingerprints.extend(_from_dom_signatures(page.dom_html))
    except Exception as exc:
        # one bad source shouldn't sink the whole fingerprint pass
        log.error("Tech-stack mapping error (continuing): %s", exc)
    result = _dedupe(fingerprints)
    log.info("Tech stack: %s", _format_for_log(result))
    return result