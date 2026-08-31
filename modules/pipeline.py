from __future__ import annotations

import datetime as _dt
from typing import Callable, Optional

from httpx import HTTPError
from pydantic import StrictStr, validate_call

from models import ScanReport, ScanStatus
from modules.ingestion.browser import ingest_target
from modules.logging_setup import get_logger
from modules.proxy.tor_manager import (
    AnonymityError, acquire_anonymous_identity, local_identity,
)
from modules.recon import knowledge_loader as kb
from modules.recon.campaign import correlate_campaign
from modules.recon.cve import cross_reference_cves
from modules.recon.features import extract_page_features, extract_ocr_text
from modules.recon.heuristics import analyze_heuristics
from modules.recon.intel import gather_intel
from modules.recon.misconfig import check_misconfigurations
from modules.recon.risk import assess_risk
from modules.recon.security_headers import audit_security
from modules.recon.techstack import map_tech_stack
from modules.recon.threatintel import check_threat_intel
from modules.recon.url_features import extract_url_features
from modules.recon.visual import assess_visual
from modules.report.generator import generate_reports
from modules.store import diff_against_previous, save_scan
from modules.util import is_loopback

log = get_logger("pipeline")

StatusHook = Optional[Callable[[str], None]]
RecoverableScanError = (HTTPError, OSError, ValueError)


def _utc_now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _emit(hook: StatusHook, report: ScanReport, status: str) -> None:
    report.status = status
    log.info("STATUS: %s", status)
    if hook is not None:
        hook(status)


@validate_call(config={"arbitrary_types_allowed": True})
async def run_scan(target_url: StrictStr, status_hook: StatusHook = None,
                   direct: bool = False) -> ScanReport:
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

    _emit(status_hook, report, ScanStatus.PROXY)
    if effective_direct:
        report.proxy = local_identity()
        log.warning("DIRECT MODE (no Tor) — loopback target %s. Not anonymous; "
                    "valid only for local decoy testing.", target_url)
    else:
        try:
            report.proxy = await acquire_anonymous_identity(target_url)
        except AnonymityError as exc:
            report.errors.append(f"Anonymity gate failed: {exc}")
            _emit(status_hook, report, ScanStatus.FAILED)
            log.critical("Aborting scan - %s", exc)
            return report

    _emit(status_hook, report, ScanStatus.INGEST)
    try:
        report.page = await ingest_target(target_url, direct=effective_direct)
        if report.page.http_status == 0 and not (report.page.dom_html or "").strip():
            report.errors.append(
                "Ingestion returned no content (page never loaded). Scam heuristics "
                "and content analysis ran against nothing — treat this scan as "
                "inconclusive, not clean.")
            log.error("Ingestion produced no content for %s", target_url)
    except RecoverableScanError as exc:
        report.errors.append(f"Ingestion failed: {exc}")
        log.error("Ingestion failed: %s", exc)

    if report.page is not None:
        try:
            report.features = extract_page_features(report.page)
            if report.page.screenshot_path:
                report.features.ocr_text = extract_ocr_text(report.page.screenshot_path)
        except RecoverableScanError as exc:
            report.errors.append(f"Feature extraction failed: {exc}")
    try:
        report.url_features = extract_url_features(target_url)
    except RecoverableScanError as exc:
        report.errors.append(f"URL feature extraction failed: {exc}")

    _emit(status_hook, report, ScanStatus.HEURISTICS)
    if report.page is not None:
        try:
            report.heuristics = analyze_heuristics(report.page, report.features)
        except RecoverableScanError as exc:
            report.errors.append(f"Heuristics failed: {exc}")

    _emit(status_hook, report, ScanStatus.VULN)
    if report.page is not None:
        try:
            report.tech_stack = map_tech_stack(report.page)
        except RecoverableScanError as exc:
            report.errors.append(f"Tech-stack mapping failed: {exc}")
        try:
            report.cves = await cross_reference_cves(report.tech_stack,
                                                     direct=effective_direct)
        except RecoverableScanError as exc:
            report.errors.append(f"CVE cross-reference failed: {exc}")
    try:
        report.misconfigs = await check_misconfigurations(target_url,
                                                          direct=effective_direct)
    except RecoverableScanError as exc:
        report.errors.append(f"Misconfig sweep failed: {exc}")

    _emit(status_hook, report, ScanStatus.SECURITY)
    if report.page is not None:
        try:
            report.security_findings = audit_security(report.page)
        except RecoverableScanError as exc:
            report.errors.append(f"Security audit failed: {exc}")

    _emit(status_hook, report, ScanStatus.INTEL)
    exit_ip = report.proxy.exit_ip if report.proxy else None
    try:
        report.intel = await gather_intel(target_url, exit_ip, direct=effective_direct)
    except RecoverableScanError as exc:
        report.errors.append(f"Domain intelligence failed: {exc}")
    try:
        report.threat_intel = await check_threat_intel(target_url, direct=effective_direct)
    except RecoverableScanError as exc:
        report.errors.append(f"Threat-intel check failed: {exc}")
    if report.page is not None and report.page.screenshot_path:
        try:
            report.visual_matches = assess_visual(report.page.screenshot_path)
        except RecoverableScanError as exc:
            report.errors.append(f"Visual matching failed: {exc}")

    if report.intel is not None:
        try:
            report.campaign = correlate_campaign(report)
        except RecoverableScanError as exc:
            report.errors.append(f"Campaign correlation failed: {exc}")

    _emit(status_hook, report, ScanStatus.SCORING)
    try:
        report.risk = assess_risk(report)
    except RecoverableScanError as exc:
        report.errors.append(f"Risk scoring failed: {exc}")

    try:
        report.diff_summary = diff_against_previous(report)
        save_scan(report)
    except RecoverableScanError as exc:
        report.errors.append(f"Case persistence failed: {exc}")

    _emit(status_hook, report, ScanStatus.REPORT)
    try:
        generate_reports(report)
    except RecoverableScanError as exc:
        report.errors.append(f"Report generation failed: {exc}")

    _emit(status_hook, report, ScanStatus.DONE)
    return report
