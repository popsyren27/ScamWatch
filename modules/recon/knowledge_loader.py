"""
knowledge_loader.py — Loads scam-detection reference data (lexicons, regex
detectors, brand lists, etc.) from external JSON files instead of hardcoding
them in heuristics.py.

Why this exists
----------------
heuristics.py used to hardcode every phrase, regex, and brand name as Python
literals. That meant updating the lexicon required touching code. This module
moves all of that reference data into a `knowledge/` folder of JSON files so
non-developers (or automated pipelines) can update signals without editing
Python at all.

Directory layout expected (override with HEURISTICS_KNOWLEDGE_DIR env var,
or by passing knowledge_dir= to load_all()):

    knowledge/
        lexicon.json              -> scam phrase lexicon
        regex_detectors.json      -> structural / URL / wallet regex signals
        obfuscation_patterns.json -> obfuscated-JS regex signals
        reference.json            -> brands, TLDs, credential hints, etc.

See knowledge/SCHEMA.md for the exact shape of each file.

Everything is loaded once and cached with functools.lru_cache. Call
`clear_cache()` (or restart the process) if you edit the JSON files at
runtime and want the changes picked up.
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Final, Pattern, Tuple

# --------------------------------------------------------------------------
# Where to find the knowledge folder.
# --------------------------------------------------------------------------
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


# --------------------------------------------------------------------------
# Public loaders — each returns the same shape heuristics.py used to hardcode.
# --------------------------------------------------------------------------

@lru_cache(maxsize=None)
def load_lexicon(knowledge_dir: str | None = None) -> Tuple[Tuple[str, str, str, int], ...]:
    """Returns (category, phrase, severity, weight) tuples."""
    data = _read_json(_knowledge_dir(knowledge_dir) / "lexicon.json")
    entries = data.get("entries", []) if isinstance(data, dict) else data
    out = []
    for i, e in enumerate(entries):
        try:
            out.append((e["category"], e["phrase"].lower(), e["severity"], int(e["weight"])))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"lexicon.json entry #{i} is malformed: {e!r}") from exc
    return tuple(out)


@lru_cache(maxsize=None)
def load_regex_detectors(
    knowledge_dir: str | None = None,
) -> Tuple[Tuple[str, str, str, int, Pattern[str]], ...]:
    """Returns (category, label, severity, weight, compiled_pattern) tuples."""
    data = _read_json(_knowledge_dir(knowledge_dir) / "regex_detectors.json")
    entries = data.get("entries", []) if isinstance(data, dict) else data
    out = []
    for i, e in enumerate(entries):
        try:
            flags = re.I if e.get("ignore_case", True) else 0
            pattern = re.compile(e["pattern"], flags)
            out.append((e["category"], e["label"], e["severity"], int(e["weight"]), pattern))
        except (KeyError, TypeError, ValueError, re.error) as exc:
            raise ValueError(f"regex_detectors.json entry #{i} is malformed: {e!r}") from exc
    return tuple(out)


@lru_cache(maxsize=None)
def load_obfuscation_patterns(
    knowledge_dir: str | None = None,
) -> Tuple[Tuple[str, Pattern[str]], ...]:
    """Returns (label, compiled_pattern) tuples."""
    data = _read_json(_knowledge_dir(knowledge_dir) / "obfuscation_patterns.json")
    entries = data.get("entries", []) if isinstance(data, dict) else data
    out = []
    for i, e in enumerate(entries):
        try:
            flags = re.I if e.get("ignore_case", True) else 0
            out.append((e["label"], re.compile(e["pattern"], flags)))
        except (KeyError, TypeError, re.error) as exc:
            raise ValueError(f"obfuscation_patterns.json entry #{i} is malformed: {e!r}") from exc
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

        # Word-boundary matchers, same as the original hardcoded version.
        self.brand_patterns: Tuple[Tuple[str, Pattern[str]], ...] = tuple(
            (b, re.compile(r"\b" + re.escape(b) + r"\b", re.I)) for b in self.ph_brands
        )


@lru_cache(maxsize=None)
def load_reference(knowledge_dir: str | None = None) -> ReferenceData:
    data = _read_json(_knowledge_dir(knowledge_dir) / "reference.json")
    if not isinstance(data, dict):
        raise ValueError("reference.json must be a JSON object, not a list.")
    return ReferenceData(data)


def clear_cache() -> None:
    """Drop all cached knowledge so the next load_* call re-reads from disk."""
    load_lexicon.cache_clear()
    load_regex_detectors.cache_clear()
    load_obfuscation_patterns.cache_clear()
    load_reference.cache_clear()