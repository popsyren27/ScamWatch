"""
risk.py — Aggregate scoring (dev notes).

Combines heuristics, CVEs, misconfigs and exposures into a 0-100 score. I try
to keep the model explainable: buckets with diminishing returns and caps.

TODO:
- Re-evaluate decay and caps after a few hundred real-world scans.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from config import (
    DOMAIN_AGE_RISK, RISK_BANDS, RISK_CATEGORY_CAPS, RISK_DECAY,
    RISK_INTEL_CAP, RISK_SEVERITY_WEIGHTS, THREATINTEL_HIT_WEIGHT,
    VISUAL_MATCH_WEIGHT,
)
from models import RiskAssessment, ScanReport
from modules.logging_setup import get_logger

log = get_logger("recon.risk")

# Security-finding categories that represent leaked secrets/data (own bucket).
_EXPOSURE_CATEGORIES = {"sensitive_exposure"}

# Heuristic categories that count as "active phishing", for the summary line.
_PHISHING_CATEGORIES = ("brand_impersonation", "credential_harvest")

# Heuristic categories/prefixes that count as "scam signals", for the summary line.
_SCAM_CATEGORIES = (
    "fake_gateway", "payment_qr", "wallet_address", "obfuscation",
    "url_anomaly", "offsite_contact", "suspicious_link", "malware_download",
)

# A domain this fresh gets called out by name in the summary, not just scored.
_YOUNG_DOMAIN_DAYS: int = 30


def _sev_weight(severity: str) -> int:
    """Turn a severity word into a number. Unknown severity just counts as 'info'."""
    return RISK_SEVERITY_WEIGHTS.get((severity or "info").lower(),
                                      RISK_SEVERITY_WEIGHTS["info"])


def _bucket_score(weights: List[int], cap: int) -> int:
    """Diminishing-returns sum of a bucket's weights, capped.

    Strongest findings count fully; each subsequent one is discounted by
    RISK_DECAY**rank so volume alone cannot dominate.
    """
    clamped = [max(0, int(w)) for w in weights]
    ranked = sorted(clamped, reverse=True)

    total = 0.0
    for rank, w in enumerate(ranked):
        total += w * (RISK_DECAY ** rank)
    return int(min(cap, round(total)))


def _band(score: int) -> str:
    """Turn a 0-100 score into a human label like 'Low' / 'Critical'."""
    level = RISK_BANDS[0][1]
    for threshold, name in RISK_BANDS:
        if score >= threshold:
            level = name
    return level


def _domain_age_weight(age_days: Optional[int]) -> int:
    """Map a domain's age in days onto a risk weight (younger == higher)."""
    if age_days is None:
        return 0
    for max_age, _severity, weight in DOMAIN_AGE_RISK:
        if age_days <= max_age:
            return weight
    return 0


def _scam_bucket(report: ScanReport) -> Tuple[int, Optional[str]]:
    """Score the raw scam/phishing heuristics into one capped bucket."""
    # fuzzy lexical hits are candidate evidence — count at half weight so a
    # soft match can never outrank an exact lexicon hit
    weights = [int(h.weight) if h.weight else _sev_weight(h.severity)
               for h in report.heuristics]
    discounted = [w // 2 if h.category == "scam_phrase_fuzzy" else w
                  for h, w in zip(report.heuristics, weights)]
    pts = _bucket_score(discounted, RISK_CATEGORY_CAPS["scam"])
    if not pts:
        return 0, None
    return pts, f"Scam heuristics: {len(report.heuristics)} signal(s) (+{pts})"


def _cve_bucket(report: ScanReport) -> Tuple[int, Optional[str]]:
    """Score known CVEs into one capped bucket."""
    weights = [_sev_weight(c.severity) for c in report.cves]
    pts = _bucket_score(weights, RISK_CATEGORY_CAPS["cve"])
    if not pts:
        return 0, None
    return pts, f"Known vulns: {len(report.cves)} (+{pts})"


def _misconfig_bucket(report: ScanReport) -> Tuple[int, Optional[str], list]:
    """Score exposed sensitive paths. Also hands back the exposed list for later."""
    exposed = [m for m in report.misconfigs if m.exposed]
    pts = _bucket_score([_sev_weight(m.severity) for m in exposed],
                         RISK_CATEGORY_CAPS["misconfig"])
    contribution = f"Exposed sensitive paths: {len(exposed)} (+{pts})" if pts else None
    return pts, contribution, exposed


def _posture_bucket(posture: list) -> Tuple[int, Optional[str]]:
    """Score general security-weakness findings (not leaked-data ones)."""
    pts = _bucket_score([_sev_weight(s.severity) for s in posture],
                         RISK_CATEGORY_CAPS["posture"])
    contribution = f"Security posture: {len(posture)} weakness(es) (+{pts})" if pts else None
    return pts, contribution


def _exposure_bucket(exposures: list) -> Tuple[int, Optional[str]]:
    """Score leaked-secret / leaked-data findings, kept separate from posture."""
    pts = _bucket_score([_sev_weight(s.severity) for s in exposures],
                         RISK_CATEGORY_CAPS["exposure"])
    contribution = f"Leaked secrets/data: {len(exposures)} (+{pts})" if pts else None
    return pts, contribution


def _split_posture_and_exposure(report: ScanReport) -> Tuple[list, list]:
    """Sort security findings into 'general weakness' vs 'leaked data' piles."""
    posture = [s for s in report.security_findings
               if s.category not in _EXPOSURE_CATEGORIES]
    exposures = [s for s in report.security_findings
                 if s.category in _EXPOSURE_CATEGORIES]
    return posture, exposures


def _intel_bucket(report: ScanReport) -> Tuple[int, Optional[str]]:
    """Score domain age + threat-feed hits + visual brand matches as one bucket."""
    weights: List[int] = []
    if report.intel:
        age_weight = _domain_age_weight(report.intel.age_days)
        if age_weight:
            weights.append(age_weight)
    weights += [THREATINTEL_HIT_WEIGHT for t in report.threat_intel if t.listed]
    weights += [VISUAL_MATCH_WEIGHT for _ in report.visual_matches]

    pts = _bucket_score(weights, RISK_INTEL_CAP)
    if not pts:
        return 0, None

    bits: List[str] = []
    if report.intel and report.intel.age_days is not None:
        bits.append(f"age {report.intel.age_days}d")
    if any(t.listed for t in report.threat_intel):
        bits.append("feed-listed")
    if report.visual_matches:
        bits.append("visual match")
    return pts, f"Intelligence ({', '.join(bits)}): (+{pts})"


def _phishing_driver(report: ScanReport) -> Optional[str]:
    """One-liner if we saw active phishing / credential harvesting signals."""
    hits = [h for h in report.heuristics if h.category in _PHISHING_CATEGORIES]
    return "active phishing / credential harvesting" if hits else None


def _scam_driver(report: ScanReport) -> Optional[str]:
    """One-liner counting generic scam signals (fake payment pages, etc.)."""
    hits = [h for h in report.heuristics
            if h.category.startswith("scam_") or h.category in _SCAM_CATEGORIES]
    return f"{len(hits)} scam signal(s)" if hits else None


def _cve_driver(report: ScanReport) -> Optional[str]:
    """One-liner counting known vulnerabilities, real CVEs preferred over advisories."""
    if not report.cves:
        return None
    real = [c for c in report.cves if c.kind == "cve"]
    return f"{len(real) or len(report.cves)} known vuln(s)"


def _threat_feed_driver(report: ScanReport) -> Optional[str]:
    """One-liner if any threat-intel feed already flagged this target."""
    return "listed on an external threat feed" if any(t.listed for t in report.threat_intel) else None


def _visual_driver(report: ScanReport) -> Optional[str]:
    """One-liner if a visual scan matched a known brand's look."""
    return "visual brand impersonation" if report.visual_matches else None


def _young_domain_driver(report: ScanReport) -> Optional[str]:
    """One-liner if the domain is suspiciously new."""
    age = report.intel.age_days if report.intel else None
    if age is not None and age <= _YOUNG_DOMAIN_DAYS:
        return f"domain only {age} day(s) old"
    return None


def _summarise(level: str, report: ScanReport, exposed_count: int, exposure_count: int) -> str:
    """Stitch together a one-sentence 'why this score' explanation."""
    drivers: List[str] = [d for d in (
        _phishing_driver(report),
        _scam_driver(report),
        _cve_driver(report),
        f"{exposed_count} exposed sensitive path(s)" if exposed_count else None,
        f"{exposure_count} leaked secret(s)" if exposure_count else None,
        _threat_feed_driver(report),
        _visual_driver(report),
        _young_domain_driver(report),
    ) if d]

    if not drivers and report.security_findings:
        drivers.append("weak security posture")

    tail = "; ".join(drivers) if drivers else "no notable findings"
    return f"{level} risk - driven by {tail}."


def _fallback_assessment() -> RiskAssessment:
    """The 'well, that broke' verdict — always safe, never leaves the report empty-handed."""
    return RiskAssessment(score=0, level="Unknown",
                           summary="Risk could not be computed.", contributions=[])


def assess_risk(report: ScanReport) -> RiskAssessment:
    """Compute the aggregate risk verdict from every finding category.

    Never raises: on any fault it returns a conservative 'Unknown' assessment
    so the report is always producible.
    """
    try:
        contributions: List[str] = []

        scam_pts, scam_line = _scam_bucket(report)
        cve_pts, cve_line = _cve_bucket(report)
        mis_pts, mis_line, exposed = _misconfig_bucket(report)

        posture, exposures = _split_posture_and_exposure(report)
        pos_pts, pos_line = _posture_bucket(posture)
        exp_pts, exp_line = _exposure_bucket(exposures)

        intel_pts, intel_line = _intel_bucket(report)

        contributions.extend(line for line in
                              (scam_line, cve_line, mis_line, pos_line, exp_line, intel_line)
                              if line)

        score = max(0, min(100, scam_pts + cve_pts + mis_pts + pos_pts
                            + exp_pts + intel_pts))
        level = _band(score)
        summary = _summarise(level, report, len(exposed), len(exposures))

        log.info("Risk score %d => %s", score, level)
        return RiskAssessment(score=int(score), level=level,
                               summary=summary, contributions=contributions)
    except Exception as exc:
        # scoring blew up somewhere — better an honest 'Unknown' than a fake number
        log.error("Risk assessment failed (returning Unknown): %s", exc)
        return _fallback_assessment()