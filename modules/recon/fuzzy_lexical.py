"""fuzzy_lexical.py — Soft lexical layer (Phase 2).

Fuzzy/co-occurrence matching of scam phrases that don't appear verbatim in
the DOM. Hits are "candidate evidence": lower weight than exact lexicon hits,
and the risk scorer treats them accordingly.

Matching pipeline per phrase:
  1. NFKC-normalize + lowercase both sides
  2. fold homoglyphs/confusables to ASCII (Cyrillic 'а' -> 'a', etc.)
  3. strip punctuation, collapse whitespace
  4. token-level fuzzy match (difflib ratio) for spelling variants

A hit fires when either:
  - every phrase token fuzzy-matches a nearby window of page tokens, or
  - the whole normalized phrase appears as a substring after folding.
"""

from __future__ import annotations

import difflib
import re
import unicodedata
from typing import List, Sequence, Tuple

from models import HeuristicHit, IngestedPage
from modules.logging_setup import get_logger
from modules.recon import knowledge_loader as kb

log = get_logger("recon.fuzzy_lexical")

# Confusables we actually see in scam evasion; not trying to be exhaustive,
# just covering the common Cyrillic/Greek/fullwidth lookalikes.
_HOMOGLYPH_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y",
    "х": "x", "і": "i", "ѕ": "s", "һ": "h", "ԁ": "d", "ɡ": "g",
    "α": "a", "ο": "o", "ρ": "p", "τ": "t", "ν": "v",
    "０": "0", "１": "1", "３": "3", "５": "5", "Ｏ": "0",
}

_PUNCT_RE = re.compile(r"[^\w\s]")
_WS_RE = re.compile(r"\s+")

_FUZZY_TOKEN_RATIO = 0.82   # difflib threshold for a single-token variant
_WINDOW_SLACK = 2           # extra tokens allowed around a phrase match


def normalize_text(text: str) -> str:
    folded = unicodedata.normalize("NFKC", text).lower()
    folded = "".join(_HOMOGLYPH_MAP.get(ch, ch) for ch in folded)
    folded = _PUNCT_RE.sub(" ", folded)
    return _WS_RE.sub(" ", folded).strip()


def _token_fuzzy_matches(phrase_tok: str, window: Sequence[str]) -> bool:
    if phrase_tok in window:
        return True
    if len(phrase_tok) < 4:
        # short tokens ("gcash", "otp") need exact matches or FP rate explodes
        return False
    return any(difflib.SequenceMatcher(None, phrase_tok, t).ratio() >= _FUZZY_TOKEN_RATIO
               for t in window)


def _phrase_in_tokens(phrase_toks: Tuple[str, ...], text_toks: List[str]) -> bool:
    span = len(phrase_toks) + _WINDOW_SLACK
    for start in range(len(text_toks) - len(phrase_toks) + 1):
        window = text_toks[start:start + span]
        if all(_token_fuzzy_matches(pt, window) for pt in phrase_toks):
            return True
    return False


def scan_fuzzy_phrases(dom_html: str) -> List[HeuristicHit]:
    """Soft-match the soft lexicon against normalized DOM text."""
    hits: List[HeuristicHit] = []
    if not dom_html:
        return hits

    # strip tags so markup doesn't glue unrelated words together
    text = re.sub(r"<[^>]+>", " ", dom_html)
    norm = normalize_text(text)
    norm_toks = norm.split()

    for rule_id, phrase_norm, language, severity, weight in kb.load_soft_lexicon():
        phrase_toks = tuple(phrase_norm.split())
        matched = False
        evidence = ""
        if phrase_norm in norm:
            matched = True
            evidence = phrase_norm
        elif phrase_toks and _phrase_in_tokens(phrase_toks, norm_toks):
            matched = True
            idx = next((i for i, t in enumerate(norm_toks)
                        if _token_fuzzy_matches(phrase_toks[0], norm_toks[i:i + 3])), None)
            ctx = norm_toks[max(0, (idx or 0) - 2):(idx or 0) + len(phrase_toks) + 4]
            evidence = " ".join(ctx)

        if matched:
            hits.append(HeuristicHit(
                category="scam_phrase_fuzzy", rule_id=rule_id,
                detail=f"Fuzzy match ({language}) for '{phrase_norm}' — candidate "
                       "evidence, not an exact lexicon hit.",
                evidence=evidence[:200], severity=severity, weight=weight))
    return hits
