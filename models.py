"""
models.py — Data shapes for scans (my quick reminder).

Short: these are strict pydantic models used as immutable evidence containers.
I forced strict types so weird coercions don't sneak into reports.

TODOs:
- Maybe freeze final `ScanReport` later if I want stronger in-memory tamper
    protection. For now the strict types are enough to catch my own mistakes.

Problems I remember:
- Pydantic's strict settings can be verbose; watch for annoying validation
    errors when testing from quick REPL inputs.
"""

from __future__ import annotations

from typing import Any, Dict, Final, List, Optional

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr


class _StrictModel(BaseModel):
    """Base model that forbids unknown fields and rejects loose coercion."""

    # extra="forbid": reject payloads carrying unexpected keys (zero-trust input).
    # strict=True: enforce exact types across the model, not just Strict* fields.
    model_config = ConfigDict(extra="forbid", strict=True)


class ScanStatus:
    """Canonical, human-readable pipeline phases surfaced to the GUI poller.

    Plain string constants, not a pydantic model — there's no runtime
    validation here, just names so callers don't hand-type status strings.
    """

    QUEUED: Final[str] = "Queued"
    PROXY: Final[str] = "Acquiring Proxy..."
    INGEST: Final[str] = "Scanning DOM..."
    HEURISTICS: Final[str] = "Analyzing Heuristics..."
    VULN: Final[str] = "Mapping Vulnerabilities..."
    SECURITY: Final[str] = "Auditing Security Posture..."
    INTEL: Final[str] = "Gathering Intelligence..."
    SCORING: Final[str] = "Scoring Risk..."
    REPORT: Final[str] = "Generating Report..."
    DONE: Final[str] = "Complete"
    FAILED: Final[str] = "Failed"


# --------------------------------------------------------------------------
# Phase 1 — Network identity evidence
# --------------------------------------------------------------------------
class ProxyIdentity(_StrictModel):
    """Proof that traffic exited via Tor and not the host's real IP."""

    host_ip: StrictStr
    exit_ip: StrictStr
    is_anonymous: StrictBool
    circuit_renewed: StrictBool


# --------------------------------------------------------------------------
# Phase 2 — Raw ingested target data
# --------------------------------------------------------------------------
class IngestedPage(_StrictModel):
    """Everything the headless browser safely lifted from the target."""

    final_url: StrictStr
    http_status: StrictInt
    response_headers: Dict[str, str] = Field(default_factory=dict)
    dom_html: StrictStr = ""
    network_requests: List[str] = Field(default_factory=list)
    screenshot_path: Optional[StrictStr] = None
    rendered: StrictBool = False


# --------------------------------------------------------------------------
# Phase 3 — Findings
# --------------------------------------------------------------------------
class TechFingerprint(_StrictModel):
    """A single identified software component, optionally versioned."""

    product: StrictStr
    version: Optional[StrictStr] = None
    source: StrictStr  # e.g. "header:Server", "meta:generator"


class CveRecord(_StrictModel):
    """A known vulnerability cross-referenced from the NVD or the offline KB.

    ``kind`` is "cve" for a real CVE id, or "advisory" for a curated non-CVE
    finding (e.g. an end-of-life runtime) so an evidence report never presents a
    pseudo-id like 'EOL-PHP' as though it were an official CVE.
    """

    cve_id: StrictStr
    severity: StrictStr
    score: Optional[float] = None
    summary: StrictStr
    matched_product: StrictStr
    kind: StrictStr = "cve"


class HeuristicHit(_StrictModel):
    """A scam signal found via QR scan, DOM regex, form analysis, etc.

    ``severity`` is one of info/low/medium/high/critical; ``weight`` is the
    point contribution toward the aggregate risk score (set by the detector so
    a strong signal like a Telegram payment route outweighs a soft urgency cue).
    """

    category: StrictStr  # e.g. "payment_qr", "scam_phrase", "fake_gateway"
    detail: StrictStr
    evidence: StrictStr = ""
    severity: StrictStr = "low"
    weight: StrictInt = 0


class MisconfigFinding(_StrictModel):
    """An exposed sensitive path (status observed only — body never read)."""

    path: StrictStr
    http_status: StrictInt
    exposed: StrictBool
    category: StrictStr = ""
    severity: StrictStr = "info"


class SecurityFinding(_StrictModel):
    """A passive web-security weakness inferred from already-captured evidence.

    Covers missing/weak response headers, insecure cookie flags, plaintext
    transport and version disclosure — all read from the Phase-2 response, never
    re-probed.
    """

    category: StrictStr  # "missing_header", "weak_cookie", "no_tls", "info_disclosure"
    detail: StrictStr
    severity: StrictStr
    evidence: StrictStr = ""


class DomainIntel(_StrictModel):
    """Registration + hosting attribution gathered passively (RDAP / CT logs).

    The fields needed to (a) score a brand-new domain as higher risk and (b)
    address an abuse report to the parties who can act: the registrar and the
    hosting provider.
    """

    domain: StrictStr = ""
    registrar: Optional[StrictStr] = None
    registrar_abuse_email: Optional[StrictStr] = None
    creation_date: Optional[StrictStr] = None
    age_days: Optional[StrictInt] = None
    nameservers: List[str] = Field(default_factory=list)
    hosting_provider: Optional[StrictStr] = None
    hosting_abuse_email: Optional[StrictStr] = None
    asn: Optional[StrictStr] = None
    favicon_hash: Optional[StrictStr] = None
    related_domains: List[str] = Field(default_factory=list)  # campaign siblings
    notes: List[str] = Field(default_factory=list)


class ThreatIntelHit(_StrictModel):
    """A reputation result from an external blocklist / threat feed."""

    source: StrictStr          # "URLhaus", "Google Safe Browsing", ...
    listed: StrictBool
    detail: StrictStr = ""
    reference: StrictStr = ""


class VisualMatch(_StrictModel):
    """A perceptual-hash match of the screenshot against a known brand page."""

    brand: StrictStr
    similarity: float          # 0.0-1.0 (1.0 == identical hash)
    reference: StrictStr = ""
    detail: StrictStr = ""


class RiskAssessment(_StrictModel):
    """Aggregate, weighted verdict synthesised from every finding category."""

    score: StrictInt          # 0-100, capped
    level: StrictStr          # Clean / Low / Medium / High / Critical
    summary: StrictStr
    contributions: List[str] = Field(default_factory=list)


# --------------------------------------------------------------------------
# Aggregate scan record
# --------------------------------------------------------------------------
class ScanReport(_StrictModel):
    """The complete, compiled finding set for one target."""

    target_url: StrictStr
    timestamp_utc: StrictStr
    status: StrictStr = ScanStatus.QUEUED
    proxy: Optional[ProxyIdentity] = None
    page: Optional[IngestedPage] = None
    tech_stack: List[TechFingerprint] = Field(default_factory=list)
    cves: List[CveRecord] = Field(default_factory=list)
    heuristics: List[HeuristicHit] = Field(default_factory=list)
    misconfigs: List[MisconfigFinding] = Field(default_factory=list)
    security_findings: List[SecurityFinding] = Field(default_factory=list)
    intel: Optional[DomainIntel] = None
    threat_intel: List[ThreatIntelHit] = Field(default_factory=list)
    visual_matches: List[VisualMatch] = Field(default_factory=list)
    risk: Optional[RiskAssessment] = None
    evidence_sha256: Dict[str, str] = Field(default_factory=dict)
    diff_summary: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dict for JSON output / templating."""
        return self.model_dump(mode="json")