"""
heuristics.py — Scam signal detectors (my short notes).

Passive detectors that scan the captured DOM/screenshot for scam indicators.
Weights and severities feed into the risk scorer.

All reference data (phrase lexicon, regex detectors, brand lists, TLDs,
credential hints, etc.) now lives OUTSIDE this file, in the `knowledge/`
folder as JSON, loaded via `knowledge_loader.py`. Edit the JSON to tune
signals — no code changes needed. See knowledge/SCHEMA.md for the format.

TODO:
- Tune weights after some real-world sampling; watch false positives on news
    sites with many keywords.
"""

from __future__ import annotations

import re
from typing import List, Optional
from urllib.parse import urlparse

from models import HeuristicHit, IngestedPage, PageFeatures
from modules.logging_setup import get_logger
from modules.recon import knowledge_loader as kb
from modules.recon import fuzzy_lexical

log = get_logger("recon.heuristics")


# --------------------------------------------------------------------------
# Knowledge, loaded once from knowledge/*.json (cached — see knowledge_loader).
# --------------------------------------------------------------------------
_SCAM_LEXICON = kb.load_lexicon()
_REGEX_DETECTORS = kb.load_regex_detectors()
_OBFUSCATION_PATTERNS = kb.load_obfuscation_patterns()
_REF = kb.load_reference()

_CURRENCY_MARKERS = _REF.currency_markers
_PH_BRANDS = _REF.ph_brands
_BRAND_OFFICIAL_DOMAINS = _REF.brand_official_domains
_BRAND_PATTERNS = _REF.brand_patterns
_SUSPICIOUS_TLDS = _REF.suspicious_tlds
_CREDENTIAL_HINTS = _REF.credential_hints
_HIGH_SEVERITY_CREDENTIAL_HINTS = _REF.high_severity_credential_hints
_PHISHY_PATH_WORDS = _REF.phishy_path_words


def _host(url: str) -> str:
    try:
        parts = urlparse(url if "://" in url else f"http://{url}")
        return (parts.hostname or "").lower()
    except Exception:
        # malformed URL — treat as an unknown host rather than crashing
        return ""


def _scan_qr(screenshot_path: str) -> List[HeuristicHit]:
    """Decode QR/barcodes in the screenshot, scoring by payload content."""
    hits: List[HeuristicHit] = []
    try:
        from PIL import Image  # type: ignore
        from pyzbar.pyzbar import decode  # type: ignore
    except ImportError as exc:
        log.warning("QR scanning unavailable (pyzbar/Pillow/zbar missing): %s", exc)
        return hits

    try:
        with Image.open(screenshot_path) as img:
            for code in decode(img):
                try:
                    payload = code.data.decode("utf-8", errors="replace")
                except Exception as exc:
                    log.debug("QR payload decode failed: %s", exc)
                    continue

                low = payload.lower()
                severity, weight = "medium", 8
                if any(k in low for k in ("telegram", "t.me", "whatsapp", "wa.me")):
                    severity, weight = "high", 14
                elif any(k in low for k in ("gcash", "maya", "paymaya", "bitcoin",
                                            "bc1", "0x", "usdt", "amount=")):
                    severity, weight = "high", 12
                hits.append(HeuristicHit(category="payment_qr", rule_id="ref.payment-qr",
                    detail=f"Embedded {code.type} QR decoded.",
                    evidence=payload[:300], severity=severity, weight=weight))
    except FileNotFoundError:
        log.warning("Screenshot %s not found for QR scan.", screenshot_path)
    except Exception as exc:
        log.error("QR scan failed: %s", exc)
    return hits


def _scan_phrases(lowered: str) -> List[HeuristicHit]:
    """Match the multi-category scam lexicon and soft currency markers."""
    hits: List[HeuristicHit] = []
    # read through the loader (lru_cached) so clear_cache() is honoured
    for rule_id, category, phrase, severity, weight in kb.load_lexicon():
        if phrase in lowered:
            hits.append(HeuristicHit(category=f"scam_{category}", rule_id=rule_id,
                detail=f"{category.title()} scam phrasing: '{phrase}'.",
                evidence=phrase, severity=severity, weight=weight))
    if any(marker in lowered for marker in _CURRENCY_MARKERS):
        hits.append(HeuristicHit(category="ph_currency", rule_id="ref.ph-currency",
            detail="Philippine peso / e-wallet currency context detected.",
            evidence="₱/PHP/GCash/Maya marker", severity="info", weight=2))
    return hits


def _scan_regex(dom_html: str) -> List[HeuristicHit]:
    hits: List[HeuristicHit] = []
    for rule_id, category, label, severity, weight, pattern in _REGEX_DETECTORS:
        seen: set = set()  # same token can match a pattern more than once
        for match in pattern.findall(dom_html):
            token = str(match)[:200]
            if token in seen:
                continue
            seen.add(token)
            hits.append(HeuristicHit(category=category, rule_id=rule_id, detail=label,
                evidence=token, severity=severity, weight=weight))
    return hits


def _scan_obfuscation(dom_html: str) -> List[HeuristicHit]:
    """Flag packed/obfuscated JS commonly used to hide phishing behaviour."""
    hits: List[HeuristicHit] = []
    for rule_id, label, pattern in _OBFUSCATION_PATTERNS:
        if pattern.search(dom_html):
            hits.append(HeuristicHit(category="obfuscation", rule_id=rule_id,
                detail=f"Obfuscated/dynamic JavaScript: {label}.",
                evidence=label, severity="medium", weight=7))
    return hits


def _scan_credential_fields(dom_html: str) -> List[HeuristicHit]:
    """Flag input fields that harvest credentials / PINs / card data."""
    hits: List[HeuristicHit] = []
    found: set = set()

    def _record(hint: str, severity: str, weight: int) -> None:
        if hint in found:
            return
        found.add(hint)
        rule_id = ("ref.credential-hint-high" if hint in _HIGH_SEVERITY_CREDENTIAL_HINTS
                   else "ref.credential-hint")
        hits.append(HeuristicHit(category="credential_harvest", rule_id=rule_id,
            detail=f"Sensitive input field collecting '{hint}'.",
            evidence=hint, severity=severity, weight=weight))

    try:
        from bs4 import BeautifulSoup  # type: ignore

        soup = BeautifulSoup(dom_html, "html.parser")
        for inp in soup.find_all("input"):
            blob = " ".join(str(inp.get(a) or "") for a in
                            ("type", "name", "id", "placeholder", "aria-label")).lower()
            if (inp.get("type") or "").lower() == "password":
                _record("password", "high", 12)
            for hint in _CREDENTIAL_HINTS:
                if hint in blob:
                    sev, wt = ("high", 14) if hint in _HIGH_SEVERITY_CREDENTIAL_HINTS else ("medium", 8)
                    _record(hint, sev, wt)
    except Exception as exc:
        # bs4 missing or parse failure — fall back to plain string matching,
        # kept conservative to avoid false alarms
        log.debug("BeautifulSoup parse failed, using regex fallback: %s", exc)
        low = dom_html.lower()
        if re.search(r"<input[^>]+type=[\"']?password", low):
            _record("password", "high", 12)
        for hint in _CREDENTIAL_HINTS:
            if hint in low:
                sev, wt = ("high", 14) if hint in _HIGH_SEVERITY_CREDENTIAL_HINTS else ("medium", 8)
                _record(hint, sev, wt)
    return hits


def _scan_brand_and_domain(lowered: str, host: str,
                           has_credential_form: bool) -> List[HeuristicHit]:
    """Detect brand impersonation (word-boundary matched) and a hostile host."""
    hits: List[HeuristicHit] = []
    on_official = any(host == d or host.endswith("." + d)
                      for d in _BRAND_OFFICIAL_DOMAINS)

    if host and not on_official:
        named = sorted({b for b, pat in _BRAND_PATTERNS if pat.search(lowered)})
        if named:
            severity, weight = ("high", 16) if has_credential_form else ("medium", 9)
            detail = ("Active phishing: PH financial brand mimicked WITH a credential "
                      "form, off the brand's official domain."
                      if has_credential_form else
                      "PH financial brand referenced on a non-official domain.")
            hits.append(HeuristicHit(category="brand_impersonation", rule_id="ref.brand-impersonation",
                detail=detail,
                evidence=f"{', '.join(named)} @ {host}", severity=severity, weight=weight))

    if host:
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            hits.append(HeuristicHit(category="domain_reputation", rule_id="ref.raw-ip-host",
                detail="Site served from a raw IP address (no domain) — common for "
                       "disposable scam infrastructure.",
                evidence=host, severity="low", weight=4))
        else:
            tld = "." + host.rsplit(".", 1)[-1] if "." in host else ""
            if tld in _SUSPICIOUS_TLDS:
                hits.append(HeuristicHit(category="domain_reputation", rule_id="ref.suspicious-tld",
                    detail=f"Host sits on a frequently-abused, throwaway TLD ({tld}).",
                    evidence=host, severity="low", weight=5))
    return hits


def _scan_url_anomalies(final_url: str, host: str) -> List[HeuristicHit]:
    """Structural URL red flags an analyst eyeballs first."""
    hits: List[HeuristicHit] = []
    if not final_url:
        return hits
    parsed = urlparse(final_url if "://" in final_url else f"http://{final_url}")

    if host.startswith("xn--") or ".xn--" in host:
        hits.append(HeuristicHit(category="url_anomaly", rule_id="ref.punycode-host",
            detail="Punycode/IDN host — may be a homograph lookalike of a real brand.",
            evidence=host, severity="medium", weight=8))
    if "@" in (parsed.netloc or ""):
        hits.append(HeuristicHit(category="url_anomaly", rule_id="ref.at-in-url",
            detail="URL embeds an '@' — the real host is AFTER it, a classic "
                   "obfuscation to disguise the destination.",
            evidence=parsed.netloc[:80], severity="high", weight=10))
    labels = host.split(".") if host else []
    if len(labels) >= 5:
        hits.append(HeuristicHit(category="url_anomaly", rule_id="ref.subdomain-depth",
            detail=f"Excessive sub-domain depth ({len(labels)} labels) — brand names "
                   "are often stuffed into sub-domains to look legitimate.",
            evidence=host, severity="low", weight=4))
    if host.count("-") >= 4:
        hits.append(HeuristicHit(category="url_anomaly", rule_id="ref.hyphen-stuffing",
            detail="Many hyphens in the host — typical of throwaway lookalike domains.",
            evidence=host, severity="low", weight=3))
    path = (parsed.path or "").lower()
    phishy = sorted({w for w in _PHISHY_PATH_WORDS if w in path})
    if phishy:
        hits.append(HeuristicHit(category="url_anomaly", rule_id="ref.phishy-path",
            detail=f"URL path contains sensitive-action keyword(s): {', '.join(phishy)}.",
            evidence=path[:120], severity="low", weight=4))
    return hits


def _dedupe(hits: List[HeuristicHit]) -> List[HeuristicHit]:
    seen: set = set()
    unique: List[HeuristicHit] = []
    for h in hits:
        key = (h.category, h.detail, h.evidence)
        if key not in seen:
            seen.add(key)
            unique.append(h)
    return unique


def analyze_heuristics(page: IngestedPage,
                       features: Optional[PageFeatures] = None) -> List[HeuristicHit]:
    """Run all passive scam heuristics over the ingested evidence.

    When a shared PageFeatures object is supplied, credential-field detection
    reads from it instead of re-parsing the DOM.
    """
    findings: List[HeuristicHit] = []
    try:
        dom = page.dom_html or ""
        lowered = dom.lower()
        host = _host(page.final_url or "")

        if page.screenshot_path:
            findings.extend(_scan_qr(page.screenshot_path))

        if features is not None:
            credential_hits = []
            for form in features.forms:
                if form.has_password:
                    credential_hits.append(HeuristicHit(category="credential_harvest",
                        rule_id="ref.credential-hint-high",
                        detail="Password input field present.",
                        evidence=form.action[:120], severity="high", weight=12))
                for hint in form.input_hints:
                    rule_id = ("ref.credential-hint-high"
                               if hint in _HIGH_SEVERITY_CREDENTIAL_HINTS
                               else "ref.credential-hint")
                    sev, wt = ("high", 14) if hint in _HIGH_SEVERITY_CREDENTIAL_HINTS else ("medium", 8)
                    credential_hits.append(HeuristicHit(category="credential_harvest",
                        rule_id=rule_id,
                        detail=f"Sensitive input field collecting '{hint}'.",
                        evidence=hint, severity=sev, weight=wt))
        else:
            credential_hits = _scan_credential_fields(dom)

        findings.extend(_scan_phrases(lowered))
        findings.extend(fuzzy_lexical.scan_fuzzy_phrases(dom))
        findings.extend(_scan_regex(dom))
        findings.extend(_scan_obfuscation(dom))
        findings.extend(credential_hits)

        # text rendered as an image dodges DOM extraction — OCR the screenshot
        # and run the same lexical layers over it
        ocr_text = features.ocr_text if features is not None else ""
        if not ocr_text and page.screenshot_path:
            from modules.recon.features import extract_ocr_text
            ocr_text = extract_ocr_text(page.screenshot_path)
        if ocr_text:
            findings.extend(_scan_phrases(ocr_text.lower()))
            findings.extend(fuzzy_lexical.scan_fuzzy_phrases(ocr_text))

        if features is not None and features.hidden_text_chunks:
            joined = " ".join(features.hidden_text_chunks).lower()
            findings.append(HeuristicHit(category="hidden_content", rule_id="feat.hidden-content",
                detail=f"CSS-hidden text present ({len(features.hidden_text_chunks)} chunk(s)) "
                       "— content invisible to users but visible to scanners.",
                evidence=joined[:200], severity="medium", weight=8))

        if features is not None and features.svg_canvas_text:
            joined = " ".join(features.svg_canvas_text)
            findings.append(HeuristicHit(category="rendered_text", rule_id="feat.svg-canvas-text",
                detail=f"Text drawn via SVG/canvas ({len(features.svg_canvas_text)} chunk(s)) "
                       "— dodges plain DOM text extraction.",
                evidence=joined[:200], severity="low", weight=4))
            findings.extend(_scan_phrases(joined.lower()))
            findings.extend(fuzzy_lexical.scan_fuzzy_phrases(joined))

        findings.extend(_scan_brand_and_domain(lowered, host,
                                               has_credential_form=bool(credential_hits)))
        findings.extend(_scan_url_anomalies(page.final_url or "", host))
    except Exception as exc:
        # heuristics are numerous and brittle against malformed DOMs — one
        # detector crashing shouldn't lose the signals already found
        log.error("Heuristic analysis error (continuing): %s", exc)
    finally:
        findings = _dedupe(findings)
        log.info("Heuristics complete: %d signal(s).", len(findings))
    return findings