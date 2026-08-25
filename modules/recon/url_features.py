"""url_features.py — URL/domain structural feature engine (Phase 3).

Pure, offline, testable. Takes a target URL and produces UrlFeatures:
subdomain depth, hyphenation, punycode, entropy, phishy path words, and
edit-distance similarity of the registrable domain to known PH brands
(typo-squat detection). Network facts (RDAP/ASN/cert) stay in intel.py —
this module never touches the network.
"""

from __future__ import annotations

import difflib
from urllib.parse import urlparse

from models import UrlFeatures
from modules.recon import knowledge_loader as kb
from modules.recon.features import shannon_entropy
from modules.recon.intel import registrable_domain
from modules.util import host_of

_REF = kb.load_reference()
_PHISHY_PATH_WORDS = _REF.phishy_path_words
_BRANDS = _REF.ph_brands

# A registrable domain this close to a brand name is treated as a lookalike.
# 'gcash-login.com' vs 'gcash' -> distance 6 is NOT flagged; 'gcaah.com' -> 1 is.
_LOOKALIKE_MAX_DISTANCE = 2


def _strip_brand_suffix(domain: str, brand: str) -> str:
    """Remove TLD labels so edit distance measures the name, not '.com'."""
    return domain.rsplit(".", 2)[0] if "." in domain else domain


def _brand_lookalike(domain: str) -> tuple[str | None, int | None]:
    if not domain or domain.replace(".", "").isdigit():
        return None, None
    name = _strip_brand_suffix(domain, "")
    best_brand, best_dist = None, None
    for brand in _BRANDS:
        dist = difflib.SequenceMatcher(None, name, brand).quick_ratio()
        # quick_ratio upper-bounds the real ratio; only refine near-misses
        if dist < 0.7:
            continue
        real = _levenshtein(name, brand)
        if best_dist is None or real < best_dist:
            best_brand, best_dist = brand, real
    if best_dist is not None and best_dist <= _LOOKALIKE_MAX_DISTANCE and best_dist > 0:
        return best_brand, best_dist
    return None, None


def _levenshtein(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > _LOOKALIKE_MAX_DISTANCE + 1:
        return _LOOKALIKE_MAX_DISTANCE + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def extract_url_features(url: str) -> UrlFeatures:
    host = host_of(url)
    parsed = urlparse(url if "://" in url else f"https://{url}")
    path = parsed.path or ""
    query = parsed.query or ""

    features = UrlFeatures(
        url=url,
        hostname=host,
        registrable_domain=registrable_domain(host),
        subdomain_depth=len(host.split(".")) if host else 0,
        hyphen_count=host.count("-"),
        is_punycode="xn--" in host,
        url_entropy=round(shannon_entropy(url), 3),
        path_depth=len([p for p in path.split("/") if p]),
        suspicious_path_words=sorted(w for w in _PHISHY_PATH_WORDS if w in path.lower()),
        query_param_count=len([kv for kv in query.split("&") if kv]) if query else 0,
        has_ip_host=bool(host and host.replace(".", "").isdigit()),
    )

    brand, dist = _brand_lookalike(features.registrable_domain)
    features.brand_lookalike_of = brand
    features.brand_lookalike_distance = dist
    return features
