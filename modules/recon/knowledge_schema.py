"""knowledge_schema.py — pydantic models for every knowledge/*.json file.

Every rule carries an identity envelope (id, version, source, confidence,
enabled, created, updated) so a fired hit can be traced back to the exact
rule that produced it, and rule performance can be measured later.
"""

from __future__ import annotations

from typing import List

from pydantic import BaseModel, ConfigDict, StrictBool, StrictFloat, StrictInt, StrictStr, field_validator

SEVERITIES = {"info", "low", "medium", "high", "critical"}


class _RuleBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: StrictStr
    version: StrictInt = 1
    source: StrictStr = ""
    confidence: StrictFloat = 0.8
    enabled: StrictBool = True
    created: StrictStr = ""
    updated: StrictStr = ""

    @field_validator("id")
    @classmethod
    def _id_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("rule id must not be empty")
        return v

    @field_validator("confidence")
    @classmethod
    def _confidence_range(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError(f"confidence must be 0.0-1.0, got {v}")
        return v


def _check_severity(v: str) -> str:
    if v not in SEVERITIES:
        raise ValueError(f"severity must be one of {sorted(SEVERITIES)}, got '{v}'")
    return v


class LexiconEntry(_RuleBase):
    category: StrictStr
    phrase: StrictStr
    severity: StrictStr = "medium"
    weight: StrictInt = 5


class SoftLexiconEntry(_RuleBase):
    """Fuzzy-matched scam phrase. Lower weight than exact lexicon by design."""
    phrase: StrictStr
    language: StrictStr = "en"
    severity: StrictStr = "low"
    weight: StrictInt = 3


class RegexDetectorEntry(_RuleBase):
    category: StrictStr
    label: StrictStr
    severity: StrictStr = "medium"
    weight: StrictInt = 5
    pattern: StrictStr
    ignore_case: StrictBool = True


class ObfuscationEntry(_RuleBase):
    label: StrictStr
    pattern: StrictStr
    ignore_case: StrictBool = True


class CookieSignatureEntry(_RuleBase):
    cookie_name: StrictStr
    product: StrictStr


class DomSignatureEntry(_RuleBase):
    product: StrictStr
    pattern: StrictStr
    ignore_case: StrictBool = True


class JsLibPatternEntry(_RuleBase):
    products: List[StrictStr]
    pattern: StrictStr
    ignore_case: StrictBool = True


class RevealingHeaderEntry(_RuleBase):
    header_name: StrictStr


class MisconfigTargetEntry(_RuleBase):
    path: StrictStr
    category: StrictStr
    severity: StrictStr = "info"


class SecurityHeaderEntry(_RuleBase):
    header_name: StrictStr
    severity_if_missing: StrictStr = "low"
    explanation: StrictStr = ""


def validate_entries(filename: str, raw: object, model: type[_RuleBase]) -> list[_RuleBase]:
    if not isinstance(raw, dict) or not isinstance(raw.get("entries"), list):
        raise ValueError(f"{filename} must be an object with an 'entries' array.")
    out: list[_RuleBase] = []
    seen_ids: set[str] = set()
    for i, e in enumerate(raw["entries"]):
        try:
            entry = model.model_validate(e)
        except Exception as exc:
            raise ValueError(f"{filename} entry #{i} failed schema validation: {exc}") from exc
        if entry.id in seen_ids:
            raise ValueError(f"{filename} entry #{i}: duplicate rule id '{entry.id}'.")
        seen_ids.add(entry.id)
        out.append(entry)
    return out
