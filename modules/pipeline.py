"""
pipeline.py — Core scan flow. My notes to self.

This sequences the phases: anonymity -> ingest -> heuristics/vuln -> intel -> reports.
Failures in non-critical phases are recorded and the scan continues; anonymity is
the hard gate (do not scan without Tor unless local testing).

TODO:
- Consider making status hooks async-safe; current hook swallowing hides errors.

Annoyances:
- Mixing sync/async in modules sometimes forces awkward imports here. Keep
    orchestration simple.
"""

from __future__ import annotations

import datetime as _dt
from typing import Callable, Optional

from pydantic import StrictStr, validate_call

from models import ScanReport, ScanStatus
from modules.ingestion.browser import ingest_target
from modules.logging_setup import get_logger
from modules.proxy.tor_manager import (
    AnonymityError, acquire_anonymous_identity, local_identity,
)
from modules.recon import knowledge_loader as kb
from modules.recon.cve import cross_reference_cves
from modules.recon.heuristics import analyze_heuristics
from modules.recon.intel import gather_intel
from modules.recon.misconfig import check_misconfigurations
from modules.recon.risk import assess_risk
from modules.recon.security_headers import audit_security
from modules.recon.techstack import map_tech_stack
from modules.recon.threatintel import check_threat_intel
from modules.recon.visual import assess_visual
from modules.report.generator import generate_reports
from modules.store import diff_against_previous, save_scan
from modules.util import is_loopback

log = get_logger("pipeline")

# A status hook lets the caller observe progress without coupling the pipeline
# to any particular UI. It is optional and its own failures are swallowed.
StatusHook = Optional[Callable[[str], None]]


def _utc_now_iso() -> str:
    """Timezone-aware UTC timestamp for the evidence record."""
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _emit(hook: StatusHook, report: ScanReport, status: str) -> None:
    """Update the report status and notify the hook, never raising."""
    report.status = status
    log.info("STATUS: %s", status)
    if hook is not None:
        try:
            hook(status)
        except Exception as exc:
            # hooks may be UI code running in the caller's context — a flaky
            # one shouldn't be able to abort the pipeline
            log.warning("Status hook raised (ignored): %s", exc)


@validate_call(config={"arbitrary_types_allowed": True})
async def run_scan(target_url: StrictStr, status_hook: StatusHook = None,
                   direct: bool = False) -> ScanReport:
    """Execute the full passive recon pipeline for one target URL.

    Returns a populated ScanReport regardless of partial failures (except a
    Phase-1 anonymity failure, which yields a FAILED report with the reason).

    ``direct=True`` bypasses Tor for LOOPBACK targets only (local decoy testing).
    It is hard-gated here: requesting direct mode for any non-loopback host is
    refused, so the anonymity guarantee can never be silently disabled against a
    real remote site.
    """
    report = ScanReport(target_url=target_url, timestamp_utc=_utc_now_iso(),
                        knowledge_version=kb.get_knowledge_version())
    local = is_loopback(target_url)

    if direct and not local:
        report.errors.append(
            "Refused: 'direct' (no-Tor) mode is permitted only for loopback "
            "targets, but this host is remote.")
        _emit(status_hook, report, ScanStatus.FAILED)
        log.critical("Aborting scan - direct mode requested for non-loopback host.")
        return report
    effective_direct = direct and local

    # `effective_direct` is the true gating flag used throughout. We compute
    # it once to keep downstream calls readable and to avoid scattered checks.

    # ---- Phase 1: Anonymity (HARD GATE) ----------------------------------
    _emit(status_hook, report, ScanStatus.PROXY)
    if effective_direct:
        # local testing: Tor cannot route to 127.0.0.1, so record the bypass openly
        report.proxy = local_identity()
        log.warning("DIRECT MODE (no Tor) — loopback target %s. Not anonymous; "
                    "valid only for local decoy testing.", target_url)
    else:
        try:
            report.proxy = await acquire_anonymous_identity(target_url)
        except AnonymityError as exc:
            # fail closed: do not touch the target without proven anonymity
            report.errors.append(f"Anonymity gate failed: {exc}")
            _emit(status_hook, report, ScanStatus.FAILED)
            log.critical("Aborting scan - %s", exc)
            return report

    # ---- Phase 2: Ingestion ----------------------------------------------
    _emit(status_hook, report, ScanStatus.INGEST)
    try:
        report.page = await ingest_target(target_url, direct=effective_direct)
    except Exception as exc:
        report.errors.append(f"Ingestion failed: {exc}")
        log.error("Ingestion failed: %s", exc)

    # ---- Phase 3a: Heuristics --------------------------------------------
    _emit(status_hook, report, ScanStatus.HEURISTICS)
    if report.page is not None:
        try:
            report.heuristics = analyze_heuristics(report.page)
        except Exception as exc:
            report.errors.append(f"Heuristics failed: {exc}")

    # ---- Phase 3b: Vulnerabilities ---------------------------------------
    _emit(status_hook, report, ScanStatus.VULN)
    if report.page is not None:
        try:
            report.tech_stack = map_tech_stack(report.page)
        except Exception as exc:
            report.errors.append(f"Tech-stack mapping failed: {exc}")
        try:
            report.cves = await cross_reference_cves(report.tech_stack,
                                                     direct=effective_direct)
        except Exception as exc:
            report.errors.append(f"CVE cross-reference failed: {exc}")
    try:
        report.misconfigs = await check_misconfigurations(target_url,
                                                          direct=effective_direct)
    except Exception as exc:
        report.errors.append(f"Misconfig sweep failed: {exc}")

    # ---- Phase 3c: Passive security-posture audit ------------------------
    _emit(status_hook, report, ScanStatus.SECURITY)
    if report.page is not None:
        try:
            report.security_findings = audit_security(report.page)
        except Exception as exc:
            report.errors.append(f"Security audit failed: {exc}")

    # ---- Phase 3d: Intelligence (RDAP, threat feeds, visual) -------------
    _emit(status_hook, report, ScanStatus.INTEL)
    exit_ip = report.proxy.exit_ip if report.proxy else None
    try:
        report.intel = await gather_intel(target_url, exit_ip, direct=effective_direct)
    except Exception as exc:
        report.errors.append(f"Domain intelligence failed: {exc}")
    try:
        report.threat_intel = await check_threat_intel(target_url, direct=effective_direct)
    except Exception as exc:
        report.errors.append(f"Threat-intel check failed: {exc}")
    if report.page is not None and report.page.screenshot_path:
        try:
            report.visual_matches = assess_visual(report.page.screenshot_path)
        except Exception as exc:
            report.errors.append(f"Visual matching failed: {exc}")

    # ---- Phase 3e: Risk synthesis (aggregate weighted verdict) -----------
    _emit(status_hook, report, ScanStatus.SCORING)
    try:
        report.risk = assess_risk(report)
    except Exception as exc:
        report.errors.append(f"Risk scoring failed: {exc}")

    # ---- Phase 4b: Case persistence + historical diff --------------------
    # diff BEFORE saving so we compare against the prior scan, then record this one
    try:
        report.diff_summary = diff_against_previous(report)
        save_scan(report)
    except Exception as exc:
        report.errors.append(f"Case persistence failed: {exc}")

    # ---- Phase 5: Reports (+ evidence integrity manifest) ----------------
    _emit(status_hook, report, ScanStatus.REPORT)
    try:
        generate_reports(report)
    except Exception as exc:
        report.errors.append(f"Report generation failed: {exc}")

    _emit(status_hook, report, ScanStatus.DONE)
    return report