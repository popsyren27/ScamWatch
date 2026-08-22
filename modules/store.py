"""
store.py — Simple SQLite history and diffs (my notes).

Store a small fingerprint per scan so history is human-readable and DB stays tiny.
I deliberately swallow storage errors so persistence never breaks a run.

TODO:
- Consider gzip-ing old fingerprints or archiving if DB grows large.
"""

# if the DB ever gets big, archive old rows before querying the full history

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager
from typing import Dict, List, Optional

from config import CASE_DB_PATH
from models import ScanReport
from modules.logging_setup import get_logger

log = get_logger("store")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url  TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    risk_level  TEXT,
    risk_score  INTEGER,
    fingerprint TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_url);
"""


@contextmanager
def _connection(db_path: str):
    """Open the scans DB (creating the schema if needed) and always close it."""
    parent = os.path.dirname(db_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript(_SCHEMA)
    try:
        yield conn
    finally:
        conn.close()


def fingerprint(report: ScanReport) -> Dict[str, object]:
    """Compact, comparable signature of a scan's salient findings."""
    dom = report.page.dom_html if report.page else ""
    return {
        "risk_level": report.risk.level if report.risk else "Unknown",
        "risk_score": report.risk.score if report.risk else 0,
        "exposed": sorted(m.path for m in report.misconfigs if m.exposed),
        "cves": sorted(c.cve_id for c in report.cves),
        "scam_categories": sorted({h.category for h in report.heuristics}),
        "secrets": sorted({s.evidence for s in report.security_findings
                           if s.category == "sensitive_exposure"}),
        # a content hash lets us cheaply detect material page changes even
        # when other findings are identical
        "dom_sha256": hashlib.sha256((dom or "").encode("utf-8", "replace")).hexdigest(),
    }


def diff_against_previous(report: ScanReport, db_path: str = CASE_DB_PATH) -> List[str]:
    """Human-readable changes vs the most recent PRIOR scan of the same target.

    Returns [] for a first-ever scan or on any error. Call BEFORE save_scan.
    """
    lines: List[str] = []
    try:
        with _connection(db_path) as conn:
            row = conn.execute(
                "SELECT fingerprint FROM scans WHERE target_url=? ORDER BY id DESC LIMIT 1",
                (report.target_url,)).fetchone()
        if not row:
            return ["First recorded scan of this target — no baseline to compare."]
        prev = json.loads(row[0])
        cur = fingerprint(report)

        if prev.get("risk_level") != cur["risk_level"]:
            lines.append(f"Risk changed: {prev.get('risk_level')} -> {cur['risk_level']} "
                         f"(score {prev.get('risk_score')} -> {cur['risk_score']}).")
        for label, key in (("exposed path", "exposed"), ("known vuln", "cves"),
                           ("scam signal", "scam_categories"), ("leaked secret", "secrets")):
            prev_set = set(prev.get(key, []))
            cur_set = set(cur[key])
            added = cur_set - prev_set
            removed = prev_set - cur_set
            if added:
                lines.append(f"New {label}(s): {', '.join(sorted(added))[:200]}.")
            if removed:
                lines.append(f"Resolved {label}(s): {', '.join(sorted(removed))[:200]}.")
        if prev.get("dom_sha256") != cur["dom_sha256"]:
            lines.append("Page content changed since the previous scan.")
        if not lines:
            lines.append("No material change since the previous scan.")
    except Exception as exc:
        log.warning("Diff against history failed (continuing): %s", exc)
    return lines


def save_scan(report: ScanReport, db_path: str = CASE_DB_PATH) -> Optional[int]:
    """Persist this scan's fingerprint. Returns the row id, or None on failure."""
    try:
        with _connection(db_path) as conn:
            cur = conn.execute(
                "INSERT INTO scans(target_url,timestamp,risk_level,risk_score,fingerprint) "
                "VALUES(?,?,?,?,?)",
                (report.target_url, report.timestamp_utc,
                 report.risk.level if report.risk else "Unknown",
                 report.risk.score if report.risk else 0,
                 json.dumps(fingerprint(report))))
            conn.commit()
            return cur.lastrowid
    except Exception as exc:
        log.error("Failed to persist scan: %s", exc)
        return None


def history(target_url: str, db_path: str = CASE_DB_PATH) -> List[Dict[str, object]]:
    """Return prior scans of a target, newest first (for a CLI 'history' view)."""
    try:
        with _connection(db_path) as conn:
            rows = conn.execute(
                "SELECT timestamp,risk_level,risk_score FROM scans WHERE target_url=? "
                "ORDER BY id DESC", (target_url,)).fetchall()
        return [{"timestamp": t, "risk_level": lvl, "risk_score": sc}
                for t, lvl, sc in rows]
    except Exception as exc:
        log.error("History query failed: %s", exc)
        return []