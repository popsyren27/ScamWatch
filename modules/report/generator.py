"""
generator.py — Build JSON/PDF evidence reports (notes to self).

Writes JSON first (always), then a PDF if ReportLab is installed. The JSON is
the canonical evidence artifact; PDF is convenience for sharing.

TODO:
- Add optional ZIP packaging of artifacts and the manifest.
"""

from __future__ import annotations

import json
import os
import re
from typing import Optional

from config import ARTIFACT_DIR
from models import ScanReport
from modules.evidence import hash_files, sha256_file, write_manifest
from modules.logging_setup import get_logger

log = get_logger("report.generator")


def _slug(url: str, ts: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", url)[:80] or "target"
    clean_ts = re.sub(r"[^0-9]", "", ts)[:14] or "report"
    return f"{stem}_{clean_ts}"


def _mark_read_only(path: str) -> None:
    """Best-effort tamper-evidence, not a security boundary."""
    try:
        os.chmod(path, 0o444)
    except Exception as exc:
        log.debug("chmod read-only failed for %s: %s", path, exc)


def write_json_report(report: ScanReport) -> Optional[str]:
    """Persist the findings as JSON. Returns the path, or None on failure."""
    try:
        os.makedirs(ARTIFACT_DIR, exist_ok=True)
        path = os.path.join(ARTIFACT_DIR,
                            f"report_{_slug(report.target_url, report.timestamp_utc)}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report.as_dict(), fh, indent=2, ensure_ascii=False)
        _mark_read_only(path)
        log.info("JSON report written: %s", path)
        return path
    except Exception as exc:
        # TODO: make CI fail loudly for this instead of just logging
        log.error("Failed to write JSON report: %s", exc)
        return None


def write_pdf_report(report: ScanReport) -> Optional[str]:
    """Render a paginated PDF evidence report. Returns None if ReportLab absent."""
    try:
        from reportlab.lib import colors  # type: ignore
        from reportlab.lib.pagesizes import A4  # type: ignore
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle  # type: ignore
        from reportlab.lib.units import cm  # type: ignore
        from reportlab.platypus import (  # type: ignore
            Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
        )
    except ImportError:
        log.warning("ReportLab not installed — skipping PDF (JSON still written).")
        return None

    try:
        os.makedirs(ARTIFACT_DIR, exist_ok=True)
        path = os.path.join(ARTIFACT_DIR,
                            f"report_{_slug(report.target_url, report.timestamp_utc)}.pdf")
        styles = getSampleStyleSheet()
        h1 = styles["Heading1"]
        h2 = styles["Heading2"]
        body = styles["BodyText"]
        mono = ParagraphStyle("mono", parent=body, fontName="Courier", fontSize=8)

        story = []
        story.append(Paragraph("THREAT-RECON — Evidence Report", h1))
        story.append(Spacer(1, 0.2 * cm))

        # --- 0. Risk verdict (headline) ------------------------------------
        # colors here are purely presentational, not implying legal certainty
        if report.risk is not None:
            band_colors = {
                "Critical": colors.HexColor("#b91c1c"),
                "High": colors.HexColor("#ea580c"),
                "Medium": colors.HexColor("#ca8a04"),
                "Low": colors.HexColor("#15803d"),
                "Clean": colors.HexColor("#15803d"),
            }
            verdict_style = ParagraphStyle(
                "verdict", parent=h2, textColor=colors.white,
                backColor=band_colors.get(report.risk.level, colors.HexColor("#334155")),
                borderPadding=6, spaceAfter=6)
            story.append(Paragraph(
                f"RISK: {report.risk.level.upper()} &nbsp;—&nbsp; score "
                f"{report.risk.score}/100", verdict_style))
            story.append(Paragraph(report.risk.summary, body))
            for c in report.risk.contributions:
                story.append(Paragraph(f"&bull; {c}", mono))
            story.append(Spacer(1, 0.3 * cm))

        # --- 1. Target & routing -------------------------------------------
        story.append(Paragraph("1. Target & Routing", h2))
        meta_rows = [
            ["Target URL", report.target_url],
            ["Timestamp (UTC)", report.timestamp_utc],
            ["Final URL", report.page.final_url if report.page else "—"],
            ["HTTP status", str(report.page.http_status) if report.page else "—"],
        ]
        if report.proxy:
            meta_rows += [
                ["Exit IP (Tor)", report.proxy.exit_ip],
                ["Host IP", report.proxy.host_ip],
                ["Anonymity verified", "YES" if report.proxy.is_anonymous else "NO"],
                ["Circuit renewed", "YES" if report.proxy.circuit_renewed else "NO"],
            ]
        story.append(_kv_table(meta_rows, Table, TableStyle, colors, cm))
        story.append(Spacer(1, 0.3 * cm))

        # --- 2. Scam heuristics --------------------------------------------
        story.append(Paragraph("2. Scam Heuristics", h2))
        if report.heuristics:
            # strongest signals first so the most incriminating evidence leads
            for h in sorted(report.heuristics, key=lambda x: -int(x.weight)):
                story.append(Paragraph(
                    f"<b>[{h.severity.upper()} · {h.category}]</b> {h.detail}", body))
                if h.evidence:
                    story.append(Paragraph(f"&nbsp;&nbsp;evidence: {h.evidence}", mono))
        else:
            story.append(Paragraph("No scam heuristics triggered.", body))
        story.append(Spacer(1, 0.3 * cm))

        # --- 3. Passive vulnerabilities ------------------------------------
        story.append(Paragraph("3. Passive Vulnerabilities", h2))
        story.append(Paragraph("Identified tech stack:", body))
        if report.tech_stack:
            for t in report.tech_stack:
                ver = f" {t.version}" if t.version else ""
                story.append(Paragraph(f"&bull; {t.product}{ver} <i>({t.source})</i>", body))
        else:
            story.append(Paragraph("None identified.", body))

        story.append(Paragraph("Known vulnerabilities &amp; advisories:", body))
        if report.cves:
            for c in report.cves:
                score = f" (CVSS {c.score})" if c.score is not None else ""
                tag = "CVE" if c.kind == "cve" else "ADVISORY"
                story.append(Paragraph(
                    f"<b>[{tag}] {c.cve_id}</b> — {c.severity}{score} "
                    f"[matched: {c.matched_product}]", body))
                if c.summary:
                    story.append(Paragraph(c.summary, mono))
        else:
            story.append(Paragraph("No known vulnerabilities cross-referenced.", body))

        story.append(Paragraph("Exposed paths (misconfiguration):", body))
        exposed = [m for m in report.misconfigs if m.exposed]
        if exposed:
            for m in sorted(exposed, key=lambda x: x.path):
                cat = f" · {m.category}" if m.category else ""
                story.append(Paragraph(
                    f"&bull; <b>[{m.severity.upper()}{cat}]</b> {m.path} — "
                    f"HTTP {m.http_status} (EXPOSED)", body))
        else:
            story.append(Paragraph("None exposed.", body))
        story.append(Spacer(1, 0.2 * cm))

        # --- 3b. Passive security posture ----------------------------------
        story.append(Paragraph("Security posture (passive header/cookie audit):", body))
        if report.security_findings:
            for s in report.security_findings:
                story.append(Paragraph(
                    f"&bull; <b>[{s.severity.upper()} · {s.category}]</b> {s.detail}", body))
        else:
            story.append(Paragraph("No passive security weaknesses observed.", body))
        story.append(Spacer(1, 0.3 * cm))

        # --- 3c. Intelligence & threat corroboration -----------------------
        story.append(Paragraph("3b. Domain Intelligence & Threat Corroboration", h2))
        i = report.intel
        if i:
            if i.age_days is not None:
                created_display = f"{i.creation_date or '—'} ({i.age_days} days old)"
            else:
                created_display = i.creation_date or "—"

            hosting_display = i.hosting_provider or "—"
            if i.asn:
                hosting_display += f" ({i.asn})"

            intel_rows = [
                ["Domain", i.domain or "—"],
                ["Registrar", i.registrar or "—"],
                ["Registrar abuse", i.registrar_abuse_email or "—"],
                ["Created", created_display],
                ["Hosting", hosting_display],
                ["Hosting abuse", i.hosting_abuse_email or "—"],
            ]
            story.append(_kv_table(intel_rows, Table, TableStyle, colors, cm))
            if i.related_domains:
                story.append(Paragraph(
                    f"<b>Campaign siblings (shared certificate):</b> "
                    f"{', '.join(i.related_domains[:12])}", body))
        else:
            story.append(Paragraph("No registration intelligence gathered.", body))

        story.append(Paragraph("External threat feeds:", body))
        if any(t.listed for t in report.threat_intel):
            for t in report.threat_intel:
                if t.listed:
                    story.append(Paragraph(f"&bull; <b>[{t.source}]</b> {t.detail}", body))
        else:
            story.append(Paragraph("Not listed on the queried feeds.", body))

        if report.visual_matches:
            story.append(Paragraph("Visual brand impersonation:", body))
            for v in report.visual_matches:
                story.append(Paragraph(
                    f"&bull; matches <b>{v.brand}</b> (similarity {v.similarity}).", body))

        if report.diff_summary:
            story.append(Paragraph("Change since previous scan:", body))
            for d in report.diff_summary:
                story.append(Paragraph(f"&bull; {d}", mono))
        story.append(Spacer(1, 0.3 * cm))

        # --- 4. Visual evidence --------------------------------------------
        story.append(Paragraph("4. Visual Evidence", h2))
        has_screenshot = (report.page and report.page.screenshot_path
                          and os.path.exists(report.page.screenshot_path))
        if has_screenshot:
            try:
                story.append(Image(report.page.screenshot_path,
                                   width=16 * cm, height=20 * cm, kind="proportional"))
            except Exception as exc:
                log.warning("Could not embed screenshot in PDF: %s", exc)
                story.append(Paragraph("Screenshot captured but could not be embedded.", body))
        else:
            story.append(Paragraph("No screenshot captured.", body))

        if report.errors:
            story.append(Spacer(1, 0.3 * cm))
            story.append(Paragraph("5. Operational Notes / Errors", h2))
            for e in report.errors:
                story.append(Paragraph(f"&bull; {e}", mono))

        SimpleDocTemplate(path, pagesize=A4).build(story)
        _mark_read_only(path)
        log.info("PDF report written: %s", path)
        return path
    except Exception as exc:
        # PDF generation failure is non-fatal; JSON is the canonical artifact
        log.error("Failed to write PDF report: %s", exc)
        return None


def _kv_table(rows, Table, TableStyle, colors, cm):
    """Build a simple 2-column key/value table for the PDF header block."""
    tbl = Table(rows, colWidths=[5 * cm, 11 * cm])
    tbl.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return tbl


def write_abuse_report(report: ScanReport) -> Optional[str]:
    """Draft a plain-text abuse report addressed to the parties who can act.

    Pre-fills the registrar / hosting abuse contacts (from RDAP intel) and a
    concise evidence summary, ready for the operator to review and send.
    """
    try:
        os.makedirs(ARTIFACT_DIR, exist_ok=True)
        path = os.path.join(ARTIFACT_DIR,
                            f"abuse_{_slug(report.target_url, report.timestamp_utc)}.txt")
        intel = report.intel
        to = []
        if intel and intel.registrar_abuse_email:
            to.append(f"Registrar abuse ({intel.registrar or 'registrar'}): "
                      f"{intel.registrar_abuse_email}")
        if intel and intel.hosting_abuse_email:
            to.append(f"Hosting abuse ({intel.hosting_provider or 'host'}): "
                      f"{intel.hosting_abuse_email}")
        to += ["Google Safe Browsing: https://safebrowsing.google.com/safebrowsing/report_phish/",
               "APWG: reportphishing@apwg.org",
               "PH (PNP-ACG): https://www.pnpacg.ph/ — NBI Cybercrime: ccd@nbi.gov.ph"]

        exposed = [m.path for m in report.misconfigs if m.exposed]
        scam = [h for h in report.heuristics if h.category.startswith("scam_")
                or h.category in ("brand_impersonation", "fake_gateway", "payment_qr")]

        age_days_display = intel.age_days if intel and intel.age_days is not None else "unknown"
        domain_age_line = (f"  Domain age     : {age_days_display} days "
                           f"(created {intel.creation_date if intel else 'unknown'})")

        hosting_provider_display = intel.hosting_provider if intel else "unknown"
        asn_display = f" ({intel.asn})" if intel and intel.asn else ""
        hosting_line = f"  Hosting        : {hosting_provider_display}{asn_display}"

        lines = [
            "ABUSE / TAKEDOWN REQUEST (draft — review before sending)",
            "=" * 64,
            f"Reported URL : {report.target_url}",
            f"Captured (UTC): {report.timestamp_utc}",
            f"Risk verdict : {report.risk.level if report.risk else 'n/a'} "
            f"({report.risk.score if report.risk else 0}/100)",
            "",
            "SEND TO:",
            *[f"  - {t}" for t in to],
            "",
            "REGISTRATION / HOSTING:",
            f"  Registrar      : {intel.registrar if intel else 'unknown'}",
            domain_age_line,
            hosting_line,
            "",
            "SUMMARY OF FINDINGS:",
            f"  - {len(scam)} scam indicator(s) detected on the page.",
            f"  - {len(exposed)} exposed sensitive path(s): "
            f"{', '.join(exposed) if exposed else 'none'}.",
            f"  - External threat feeds: "
            f"{'LISTED' if any(t.listed for t in report.threat_intel) else 'no hit'}.",
        ]
        if report.visual_matches:
            lines.append(f"  - Visual brand impersonation of: "
                         f"{', '.join(v.brand for v in report.visual_matches)}.")
        if intel and intel.related_domains:
            lines.append(f"  - Possible campaign siblings (shared cert): "
                         f"{', '.join(intel.related_domains[:8])}.")
        lines += ["",
                  "Full technical evidence (PDF/JSON) and a SHA-256 integrity manifest "
                  "are attached.",
                  "This report was generated by an automated passive scanner; please "
                  "verify independently before action."]
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        log.info("Abuse report drafted: %s", path)
        return path
    except Exception as exc:
        log.error("Failed to draft abuse report: %s", exc)
        return None


def generate_reports(report: ScanReport) -> dict[str, Optional[str]]:
    """Write all report formats + an integrity manifest. JSON is guaranteed."""
    # hash the screenshot first so the JSON snapshot can record it, even if
    # PDF generation fails afterward
    if report.page and report.page.screenshot_path:
        digest = sha256_file(report.page.screenshot_path)
        if digest:
            report.evidence_sha256[os.path.basename(report.page.screenshot_path)] = digest

    json_path = write_json_report(report)
    pdf_path = write_pdf_report(report)
    abuse_path = write_abuse_report(report)

    artifacts = [p for p in (json_path, pdf_path, abuse_path,
                             report.page.screenshot_path if report.page else None) if p]
    report.evidence_sha256.update(hash_files(artifacts))
    manifest_path = write_manifest(ARTIFACT_DIR, report.target_url,
                                   report.timestamp_utc, report.evidence_sha256)
    return {"json": json_path, "pdf": pdf_path, "abuse": abuse_path,
            "manifest": manifest_path}