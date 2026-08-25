"""features.py — Shared page-feature extraction (Phase 3).

One normalization pass over IngestedPage: parse the DOM once, extract forms,
links, scripts, payment destinations, brand mentions, hidden content, and
hand a PageFeatures object to every detector. Detectors read fields; they
don't re-parse HTML.

OCR is filled in lazily by the caller if a screenshot exists (see
extract_ocr_text) so the heavy pytesseract dependency stays optional.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlparse

from models import (
    FormFeature, IngestedPage, LinkFeature, PageFeatures, PaymentDestination,
)
from modules.logging_setup import get_logger
from modules.recon import knowledge_loader as kb
from modules.util import host_of

log = get_logger("recon.features")

_REF = kb.load_reference()
_BRAND_PATTERNS = _REF.brand_patterns
_CREDENTIAL_HINTS = _REF.credential_hints

# e-wallet / mobile numbers: PH format 09XXXXXXXXX or +639XXXXXXXXX
_PH_PHONE = re.compile(r"(?:\+639|09)\d{9}\b")
# crypto wallets — conservative shapes to keep FP rate sane
_BTC_ADDR = re.compile(r"\b(?:bc1[a-z0-9]{20,}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_ETH_ADDR = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_EWALLET_NUMBERS = ("gcash", "maya", "paymaya")

_TAG_STRIP_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")

# CSS that hides content from a human while keeping it in the DOM/text layer.
_HIDDEN_STYLE_RE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|"
    r"text-indent\s*:\s*-?\d{3,}px|position\s*:\s*absolute[^}]*?left\s*:\s*-?\d{4,}px",
    re.I,
)

# Rough language guess from stopword frequency; good enough to route the
# lexical layers, not a real identifier.
_LANG_STOPWORDS = {
    "en": {"the", "and", "for", "you", "your", "with", "this", "that", "have",
           "from", "our", "not", "are", "will", "can"},
    "tl": {"ang", "ng", "sa", "mga", "po", "para", "hindi", "ito", "na", "yung",
           "kung", "lang", "din", "rin"},
}


def _soup(dom_html: str):
    from bs4 import BeautifulSoup  # type: ignore
    return BeautifulSoup(dom_html, "html.parser")


def _absolutize(base_url: str, href: str) -> str:
    from urllib.parse import urljoin
    try:
        return urljoin(base_url or "", href.strip())
    except ValueError:
        return href


def _extract_forms(soup, host: str) -> list[FormFeature]:
    out = []
    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        parsed = urlparse(action)
        action_host = (parsed.hostname or "").lower() if parsed.scheme else ""
        external = bool(action_host and action_host != host)

        hints: set[str] = set()
        has_password = False
        for inp in form.find_all("input"):
            blob = " ".join(str(inp.get(a) or "") for a in
                            ("type", "name", "id", "placeholder", "aria-label")).lower()
            if (inp.get("type") or "").lower() == "password":
                has_password = True
            for hint in _CREDENTIAL_HINTS:
                if hint in blob:
                    hints.add(hint)

        out.append(FormFeature(
            action=action[:300], method=(form.get("method") or "get").lower(),
            external_action=external, input_hints=sorted(hints),
            has_password=has_password))
    return out


def _extract_links(soup, base_url: str, host: str) -> list[LinkFeature]:
    out = []
    seen: set[str] = set()
    for a in soup.find_all("a"):
        href = (a.get("href") or "").strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        full = _absolutize(base_url, href)
        if full in seen:
            continue
        seen.add(full)
        link_host = (urlparse(full).hostname or "").lower()
        text = _WS_RE.sub(" ", a.get_text(" ", strip=True))[:120]
        out.append(LinkFeature(href=full[:500], external=bool(link_host and link_host != host),
                               text=text))
    return out


def _extract_scripts_and_iframes(soup) -> tuple[list[str], list[str]]:
    scripts, iframes = [], []
    for s in soup.find_all("script", src=True):
        scripts.append(str(s.get("src"))[:500])
    for f in soup.find_all("iframe"):
        src = f.get("src") or ""
        if src:
            iframes.append(src[:500])
    return scripts, iframes


def _visible_text(soup) -> str:
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    return _WS_RE.sub(" ", soup.get_text(" ", strip=True))


def _hidden_text_chunks(dom_html: str) -> list[str]:
    """Text inside elements whose inline style hides it from view."""
    chunks = []
    # crude but effective: find styled tags, strip their tags, keep their text
    for m in re.finditer(r"<(\w+)[^>]*style=[\"']([^\"']*)[\"'][^>]*>(.*?)</\1>",
                         dom_html, re.S | re.I):
        style, inner = m.group(2), m.group(3)
        if _HIDDEN_STYLE_RE.search(style):
            text = _WS_RE.sub(" ", _TAG_STRIP_RE.sub(" ", inner)).strip()
            if text:
                chunks.append(text[:500])
    return chunks


_SVG_TEXT_RE = re.compile(r"<text[^>]*>(.*?)</text>", re.S | re.I)
_CANVAS_CALL_RE = re.compile(
    r"(?:fillText|strokeText)\s*\(\s*[\"']([^\"']{4,200})[\"']", re.I)


def _svg_and_canvas_text(dom_html: str) -> list[str]:
    """Text inside <svg><text> and canvas fillText/strokeText calls.

    Both dodge plain DOM text extraction, so they're pulled out explicitly.
    """
    chunks = [ _WS_RE.sub(" ", _TAG_STRIP_RE.sub(" ", m.group(1))).strip()
               for m in _SVG_TEXT_RE.finditer(dom_html) ]
    chunks.extend(m.group(1).strip() for m in _CANVAS_CALL_RE.finditer(dom_html))
    return [c for c in chunks if c][:20]


def _detect_language(text: str) -> str:
    words = set(re.findall(r"[a-z]+", text.lower()))
    if not words:
        return ""
    scores = {lang: len(words & stops) for lang, stops in _LANG_STOPWORDS.items()}
    best = max(scores, key=scores.get)
    return best if scores[best] >= 3 else ""


def _brand_mentions(lowered_text: str) -> list[str]:
    return sorted({b for b, pat in _BRAND_PATTERNS if pat.search(lowered_text)})


def _payment_destinations(dom_html: str, visible: str) -> list[PaymentDestination]:
    blob = dom_html + "\n" + visible
    out: list[PaymentDestination] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str, source: str) -> None:
        key = (kind, value)
        if key not in seen:
            seen.add(key)
            out.append(PaymentDestination(kind=kind, value=value[:200], source=source))

    low = blob.lower()
    for wallet in ("gcash", "maya", "paymaya"):
        for num in _PH_PHONE.findall(blob):
            # only attribute the number to a wallet when named nearby
            idx = low.find(num.lower())
            window = low[max(0, idx - 60):idx + len(num) + 60]
            if wallet in window:
                add(wallet, num, "dom")
                break

    for m in _BTC_ADDR.finditer(blob):
        add("wallet_btc", m.group(0), "dom")
    for m in _ETH_ADDR.finditer(blob):
        add("wallet_eth", m.group(0), "dom")
    return out[:20]


def _phone_numbers(blob: str) -> list[str]:
    return sorted(set(_PH_PHONE.findall(blob)))[:20]


def extract_page_features(page: IngestedPage) -> PageFeatures:
    """Single normalization pass. Never raises on malformed DOM — partial beats none."""
    features = PageFeatures(url=page.final_url, hostname=host_of(page.final_url))
    dom = page.dom_html or ""
    if not dom:
        return features

    try:
        soup = _soup(dom)
    except Exception as exc:
        log.warning("DOM parse failed (%s) — returning URL-only features.", exc)
        return features

    features.title = _WS_RE.sub(" ", soup.title.get_text(strip=True))[:300] if soup.title else ""
    features.forms = _extract_forms(soup, features.hostname)
    features.links = _extract_links(soup, page.final_url, features.hostname)[:200]
    features.scripts, features.iframes = _extract_scripts_and_iframes(soup)
    visible = _visible_text(soup)  # decomposes script/style — must run after extraction
    features.visible_text = visible[:50_000]
    features.hidden_text_chunks = _hidden_text_chunks(dom)
    features.svg_canvas_text = _svg_and_canvas_text(dom)
    features.brand_mentions = _brand_mentions((dom + " " + visible).lower())
    features.payment_destinations = _payment_destinations(dom, visible)
    features.phone_numbers = _phone_numbers(dom + "\n" + visible)
    features.language = _detect_language(visible)
    features.redirect_chain = list(page.network_requests)[:30]
    return features


def extract_ocr_text(screenshot_path: str) -> str:
    """Best-effort OCR of the screenshot; empty string if tesseract is missing."""
    try:
        import pytesseract  # type: ignore
        from PIL import Image  # type: ignore
    except ImportError as exc:
        log.info("OCR unavailable (pytesseract/Pillow missing): %s", exc)
        return ""
    try:
        with Image.open(screenshot_path) as img:
            return _WS_RE.sub(" ", pytesseract.image_to_string(img)).strip()
    except Exception as exc:
        log.info("OCR failed for %s: %s", screenshot_path, exc)
        return ""


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())
