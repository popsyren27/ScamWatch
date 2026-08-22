"""
knowledge_loader.py — Loads scam-detection reference data from knowledge/*.json.

Every scored rule carries an identity envelope (id, version, source,
confidence, enabled, created, updated) validated by pydantic models in
knowledge_schema.py. Loaders return tuples that include the rule id so hits
can be attributed to the exact rule that fired.

Files are wrapped as {"schema_version": 1, "knowledge_version": "...",
"entries": [...]}. get_knowledge_version() returns the aggregate version
stamped onto every ScanReport.

Everything is loaded once and cached with functools.lru_cache. Call
clear_cache() (or restart) after editing JSON at runtime.
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Final, Pattern, Tuple

from modules.recon.knowledge_schema import (
    CookieSignatureEntry, DomSignatureEntry, JsLibPatternEntry,
    LexiconEntry, MisconfigTargetEntry, ObfuscationEntry,
    RegexDetectorEntry, RevealingHeaderEntry, SecurityHeaderEntry,
    validate_entries,
)

DEFAULT_KNOWLEDGE_DIR: Final[Path] = Path(__file__).resolve().parent / "knowledge"


def _knowledge_dir(knowledge_dir: str | os.PathLike | None = None) -> Path:
    if knowledge_dir is not None:
        return Path(knowledge_dir)
    env_override = os.environ.get("HEURISTICS_KNOWLEDGE_DIR")
    if env_override:
        return Path(env_override)
    return DEFAULT_KNOWLEDGE_DIR


def _read_json(path: Path) -> object:
    if not path.exists():
        raise FileNotFoundError(
            f"Knowledge file not found: {path}. "
            "Populate it (see knowledge/SCHEMA.md) or point "
            "HEURISTICS_KNOWLEDGE_DIR at the right folder."
        )
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc


@lru_cache(maxsize=None)
def load_lexicon(knowledge_dir: str | None = None) -> Tuple[Tuple[str, str, str, str, int], ...]:
    """Returns (rule_id, category, phrase, severity, weight) tuples."""
    raw = _read_json(_knowledge_dir(knowledge_dir) / "lexicon.json")
    entries = validate_entries("lexicon.json", raw, LexiconEntry)
    return tuple(
        (e.id, e.category, e.phrase.lower(), e.severity, e.weight)
        for e in entries if e.enabled
    )


@lru_cache(maxsize=None)
def load_regex_detectors(
    knowledge_dir: str | None = None,
) -> Tuple[Tuple[str, str, str, str, int, Pattern[str]], ...]:
    """Returns (rule_id, category, label, severity, weight, compiled_pattern)."""
    raw = _read_json(_knowledge_dir(knowledge_dir) / "regex_detectors.json")
    entries = validate_entries("regex_detectors.json", raw, RegexDetectorEntry)
    out = []
    for e in entries:
        if not e.enabled:
            continue
        flags = re.I if e.ignore_case else 0
        try:
            pattern = re.compile(e.pattern, flags)
        except re.error as exc:
            raise ValueError(f"regex_detectors.json rule '{e.id}': bad pattern: {exc}") from exc
        out.append((e.id, e.category, e.label, e.severity, e.weight, pattern))
    return tuple(out)


@lru_cache(maxsize=None)
def load_obfuscation_patterns(
    knowledge_dir: str | None = None,
) -> Tuple[Tuple[str, str, Pattern[str]], ...]:
    """Returns (rule_id, label, compiled_pattern) tuples."""
    raw = _read_json(_knowledge_dir(knowledge_dir) / "obfuscation_patterns.json")
    entries = validate_entries("obfuscation_patterns.json", raw, ObfuscationEntry)
    out = []
    for e in entries:
        if not e.enabled:
            continue
        flags = re.I if e.ignore_case else 0
        try:
            out.append((e.id, e.label, re.compile(e.pattern, flags)))
        except re.error as exc:
            raise ValueError(f"obfuscation_patterns.json rule '{e.id}': bad pattern: {exc}") from exc
    return tuple(out)


class ReferenceData:
    """Bundle of small reference lists + derived, pre-compiled lookups."""

    __slots__ = (
        "currency_markers",
        "ph_brands",
        "brand_official_domains",
        "brand_patterns",
        "suspicious_tlds",
        "credential_hints",
        "high_severity_credential_hints",
        "phishy_path_words",
    )

    def __init__(self, raw: dict):
        def _tuple_of_str(key: str) -> Tuple[str, ...]:
            return tuple(str(x).lower() for x in raw.get(key, []))

        self.currency_markers = _tuple_of_str("currency_markers")
        self.ph_brands = _tuple_of_str("ph_brands")
        self.brand_official_domains = _tuple_of_str("brand_official_domains")
        self.suspicious_tlds = _tuple_of_str("suspicious_tlds")
        self.credential_hints = _tuple_of_str("credential_hints")
        self.high_severity_credential_hints = _tuple_of_str("high_severity_credential_hints")
        self.phishy_path_words = _tuple_of_str("phishy_path_words")

        self.brand_patterns: Tuple[Tuple[str, Pattern[str]], ...] = tuple(
            (b, re.compile(r"\b" + re.escape(b) + r"\b", re.I)) for b in self.ph_brands
        )


@lru_cache(maxsize=None)
def load_reference(knowledge_dir: str | None = None) -> ReferenceData:
    data = _read_json(_knowledge_dir(knowledge_dir) / "reference.json")
    if not isinstance(data, dict):
        raise ValueError("reference.json must be a JSON object.")
    return ReferenceData(data)


# --------------------------------------------------------------------------
# Tech-stack signatures (moved out of techstack.py)
# --------------------------------------------------------------------------

@lru_cache(maxsize=None)
def load_revealing_headers(knowledge_dir: str | None = None) -> Tuple[Tuple[str, str], ...]:
    """Returns (rule_id, header_name_lowercase) tuples."""
    raw = _read_json(_knowledge_dir(knowledge_dir) / "tech_signatures.json")
    entries = validate_entries("tech_signatures.json [revealing_headers]",
                               {"entries": raw.get("revealing_headers", [])},
                               RevealingHeaderEntry)
    return tuple((e.id, e.header_name.lower()) for e in entries if e.enabled)


@lru_cache(maxsize=None)
def load_cookie_signatures(knowledge_dir: str | None = None) -> Tuple[Tuple[str, str, str], ...]:
    """Returns (rule_id, cookie_name_lowercase, product) tuples."""
    raw = _read_json(_knowledge_dir(knowledge_dir) / "tech_signatures.json")
    entries = validate_entries("tech_signatures.json [cookie_signatures]",
                               {"entries": raw.get("cookie_signatures", [])},
                               CookieSignatureEntry)
    return tuple((e.id, e.cookie_name.lower(), e.product) for e in entries if e.enabled)


@lru_cache(maxsize=None)
def load_dom_signatures(
    knowledge_dir: str | None = None,
) -> Tuple[Tuple[str, str, Pattern[str]], ...]:
    """Returns (rule_id, product, compiled_pattern) tuples."""
    raw = _read_json(_knowledge_dir(knowledge_dir) / "tech_signatures.json")
    entries = validate_entries("tech_signatures.json [dom_signatures]",
                               {"entries": raw.get("dom_signatures", [])},
                               DomSignatureEntry)
    out = []
    for e in entries:
        if not e.enabled:
            continue
        flags = re.I if e.ignore_case else 0
        try:
            out.append((e.id, e.product, re.compile(e.pattern, flags)))
        except re.error as exc:
            raise ValueError(f"tech_signatures.json rule '{e.id}': bad pattern: {exc}") from exc
    return tuple(out)


@lru_cache(maxsize=None)
def load_js_lib_patterns(
    knowledge_dir: str | None = None,
) -> Tuple[Tuple[str, Tuple[str, ...], Pattern[str]], ...]:
    """Returns (rule_id, products, compiled_pattern) tuples."""
    raw = _read_json(_knowledge_dir(knowledge_dir) / "tech_signatures.json")
    entries = validate_entries("tech_signatures.json [js_lib_patterns]",
                               {"entries": raw.get("js_lib_patterns", [])},
                               JsLibPatternEntry)
    out = []
    for e in entries:
        if not e.enabled:
            continue
        flags = re.I if e.ignore_case else 0
        try:
            out.append((e.id, tuple(p.lower() for p in e.products), re.compile(e.pattern, flags)))
        except re.error as exc:
            raise ValueError(f"tech_signatures.json rule '{e.id}': bad pattern: {exc}") from exc
    return tuple(out)


# --------------------------------------------------------------------------
# Posture targets (misconfig paths + expected security headers)
# --------------------------------------------------------------------------

@lru_cache(maxsize=None)
def load_misconfig_targets(
    knowledge_dir: str | None = None,
) -> Tuple[Tuple[str, str, str, str], ...]:
    """Returns (rule_id, path, category, severity) tuples."""
    raw = _read_json(_knowledge_dir(knowledge_dir) / "posture_targets.json")
    entries = validate_entries("posture_targets.json [misconfig_targets]",
                               {"entries": raw.get("misconfig_targets", [])},
                               MisconfigTargetEntry)
    return tuple((e.id, e.path, e.category, e.severity) for e in entries if e.enabled)


@lru_cache(maxsize=None)
def load_security_headers_expected(
    knowledge_dir: str | None = None,
) -> Tuple[Tuple[str, str, str, str], ...]:
    """Returns (rule_id, header_name, severity_if_missing, explanation) tuples."""
    raw = _read_json(_knowledge_dir(knowledge_dir) / "posture_targets.json")
    entries = validate_entries("posture_targets.json [security_headers_expected]",
                               {"entries": raw.get("security_headers_expected", [])},
                               SecurityHeaderEntry)
    return tuple((e.id, e.header_name.lower(), e.severity_if_missing, e.explanation)
                 for e in entries if e.enabled)


# --------------------------------------------------------------------------
# Aggregate knowledge version
# --------------------------------------------------------------------------

_VERSIONED_FILES: Final[Tuple[str, ...]] = (
    "lexicon.json", "regex_detectors.json", "obfuscation_patterns.json",
    "reference.json", "tech_signatures.json", "posture_targets.json",
)


@lru_cache(maxsize=None)
def get_knowledge_version(knowledge_dir: str | None = None) -> str:
    """Dot-joined per-file knowledge versions; files missing the field are skipped."""
    parts = []
    for fname in _VERSIONED_FILES:
        try:
            data = _read_json(_knowledge_dir(knowledge_dir) / fname)
        except FileNotFoundError:
            continue
        if isinstance(data, dict):
            kv = data.get("knowledge_version")
            if kv:
                parts.append(str(kv))
    return ".".join(parts) if parts else "unknown"


def clear_cache() -> None:
    """Drop all cached knowledge so the next load_* call re-reads from disk."""
    load_lexicon.cache_clear()
    load_regex_detectors.cache_clear()
    load_obfuscation_patterns.cache_clear()
    load_reference.cache_clear()
    load_revealing_headers.cache_clear()
    load_cookie_signatures.cache_clear()
    load_dom_signatures.cache_clear()
    load_js_lib_patterns.cache_clear()
    load_misconfig_targets.cache_clear()
    load_security_headers_expected.cache_clear()
    get_knowledge_version.cache_clear()
