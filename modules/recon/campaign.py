"""campaign.py — Infrastructure graph + campaign clustering.

Every scan drops its infrastructure fingerprints (favicon hash, wallets,
phones, Telegram handles, analytics IDs, reused JS, hosting, nameservers)
into a small SQLite store. Domains sharing strong keys get unioned into a
campaign; a campaign's reputation comes from how its members were scored.
A brand-new domain clustered into a known-bad campaign inherits risk instead
of starting from zero evidence.
"""

from __future__ import annotations

import datetime as _dt
import os
import re
import sqlite3
from contextlib import contextmanager
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from config import (
    CAMPAIGN_DB_PATH, CAMPAIGN_INHERIT_CAP, CAMPAIGN_INHERIT_WEIGHT,
)
from models import CampaignMatch, ScanReport
from modules.logging_setup import get_logger

log = get_logger("recon.campaign")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS obs (
    domain    TEXT NOT NULL,
    ktype     TEXT NOT NULL,
    kvalue    TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (domain, ktype, kvalue)
);
CREATE TABLE IF NOT EXISTS verdicts (
    domain   TEXT PRIMARY KEY,
    level    TEXT NOT NULL,
    score    INTEGER NOT NULL,
    listed   INTEGER NOT NULL,
    updated  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS membership (
    campaign_id INTEGER NOT NULL,
    domain      TEXT NOT NULL,
    PRIMARY KEY (campaign_id, domain)
);
"""

# key type -> clustering strength. "strong" keys cluster on their own;
# two distinct "medium" keys cluster; "weak" keys are recorded but never
# join two domains by themselves (shared hosting is too common).
_STRONG = {"wallet", "phone", "telegram", "favicon"}
_MEDIUM = {"analytics", "js_asset"}

_ANALYTICS_RE = re.compile(
    r"\b(UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{6,12}|GTM-[A-Z0-9]{5,}|aw-\d{9,})", re.I)
_FB_PIXEL_RE = re.compile(r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{8,})['\"]")
_TELEGRAM_RE = re.compile(r"(?:t\.me|telegram\.me)/(@?[A-Za-z0-9_]{4,32})")


@contextmanager
def _connection(db_path: str = CAMPAIGN_DB_PATH):
    parent = os.path.dirname(db_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript(_SCHEMA)
    try:
        yield conn
    finally:
        conn.close()


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def extract_keys(report: ScanReport) -> List[Tuple[str, str]]:
    """Infrastructure fingerprints for this scan's registrable domain."""
    keys: List[Tuple[str, str]] = []
    seen: Set[Tuple[str, str]] = set()

    def add(ktype: str, value: str) -> None:
        value = value.strip().lower()
        if value and (ktype, value) not in seen:
            seen.add((ktype, value))
            keys.append((ktype, value))

    dom = report.intel.domain if report.intel else ""
    if not dom:
        return keys

    if report.intel and report.intel.favicon_hash:
        add("favicon", report.intel.favicon_hash)

    feats = report.features
    if feats:
        for p in feats.payment_destinations:
            add("wallet", f"{p.kind}:{p.value}")
        for phone in feats.phone_numbers:
            add("phone", phone)
        blob = feats.visible_text + "\n" + (report.page.dom_html if report.page else "")
        for m in _TELEGRAM_RE.finditer(blob):
            add("telegram", m.group(1))
        for m in _ANALYTICS_RE.finditer(blob):
            add("analytics", m.group(1))
        for m in _FB_PIXEL_RE.finditer(blob):
            add("analytics", f"fb:{m.group(1)}")
        for src in feats.scripts:
            parsed = urlparse(src)
            if parsed.netloc and parsed.path:
                add("js_asset", parsed.netloc + parsed.path)

    # crt.sh siblings are direct domain-to-domain edges
    if report.intel:
        for sibling in report.intel.related_domains:
            sib_dom = sibling.strip().lower()
            if sib_dom and sib_dom != dom:
                add("cert_sibling", sib_dom)

    return keys


def _record(conn: sqlite3.Connection, report: ScanReport, keys: List[Tuple[str, str]]) -> None:
    dom = report.intel.domain
    now = _now()
    for ktype, kvalue in keys:
        conn.execute(
            "INSERT INTO obs(domain,ktype,kvalue,last_seen) VALUES(?,?,?,?) "
            "ON CONFLICT(domain,ktype,kvalue) DO UPDATE SET last_seen=excluded.last_seen",
            (dom, ktype, kvalue, now))

    listed = int(any(t.listed for t in report.threat_intel))
    level = report.risk.level if report.risk else "Unknown"
    score = report.risk.score if report.risk else 0
    conn.execute(
        "INSERT INTO verdicts(domain,level,score,listed,updated) VALUES(?,?,?,?,?) "
        "ON CONFLICT(domain) DO UPDATE SET level=excluded.level, score=excluded.score, "
        "listed=max(listed, excluded.listed), updated=excluded.updated",
        (dom, level, score, listed, now))
    conn.commit()


def _load_graph(conn: sqlite3.Connection) -> Tuple[Dict[str, List[Tuple[str, str]]], Dict[str, dict]]:
    """All known observations plus each domain's latest verdict."""
    obs: Dict[str, List[Tuple[str, str]]] = {}
    for dom, ktype, kvalue in conn.execute("SELECT domain,ktype,kvalue FROM obs"):
        obs.setdefault(dom, []).append((ktype, kvalue))
    verdicts: Dict[str, dict] = {}
    for dom, level, score, listed in conn.execute(
            "SELECT domain,level,score,listed FROM verdicts"):
        verdicts[dom] = {"level": level, "score": score, "listed": bool(listed)}
    return obs, verdicts


def _edges(obs: Dict[str, List[Tuple[str, str]]]) -> List[Tuple[str, str]]:
    """Domain pairs that should be in the same campaign."""
    by_key: Dict[Tuple[str, str], Set[str]] = {}
    for dom, keys in obs.items():
        for k in keys:
            by_key.setdefault(k, set()).add(dom)

    pair_medium: Dict[Tuple[str, str], int] = {}
    edges: List[Tuple[str, str]] = []
    for (ktype, _kvalue), holders in by_key.items():
        if ktype == "cert_sibling":
            # value IS the other domain; handled below, skip pairwise here
            continue
        domains = sorted(holders)
        for i, a in enumerate(domains):
            for b in domains[i + 1:]:
                if ktype in _STRONG:
                    edges.append((a, b))
                elif ktype in _MEDIUM:
                    pair = (a, b)
                    pair_medium[pair] = pair_medium.get(pair, 0) + 1

    edges.extend(pair for pair, count in pair_medium.items() if count >= 2)

    for dom, keys in obs.items():
        for ktype, kvalue in keys:
            if ktype == "cert_sibling" and kvalue in obs:
                edges.append((dom, kvalue))
    return edges


def _components(nodes: Set[str], edges: List[Tuple[str, str]]) -> List[Set[str]]:
    parent = {n: n for n in nodes}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for a, b in edges:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    groups: Dict[str, Set[str]] = {}
    for n in nodes:
        groups.setdefault(find(n), set()).add(n)
    return list(groups.values())


def _is_bad(verdict: dict) -> bool:
    return verdict["listed"] or verdict["level"] in ("High", "Critical")


def correlate_campaign(report: ScanReport,
                       db_path: str = CAMPAIGN_DB_PATH) -> Optional[CampaignMatch]:
    """Record this scan's infra keys, then cluster and score its campaign."""
    keys = extract_keys(report)
    if not keys:
        return None

    with _connection(db_path) as conn:
        _record(conn, report, keys)
        obs, verdicts = _load_graph(conn)

    components = _components(set(obs), _edges(obs))
    mine = report.intel.domain
    cluster = next((c for c in components if mine in c), {mine})
    members = sorted(cluster - {mine})

    shared: List[str] = []
    my_keys = set(obs.get(mine, []))
    for member in members:
        overlap = my_keys & set(obs.get(member, []))
        for ktype, kvalue in sorted(overlap):
            label = kvalue if ktype == "cert_sibling" else f"{ktype}={kvalue}"
            shared.append(f"{member}: {label}")

    bad_members = [m for m in members if m in verdicts and _is_bad(verdicts[m])]
    worst = max((verdicts[m]["score"] for m in members if m in verdicts), default=0)

    with _connection(db_path) as conn:
        row = conn.execute(
            "SELECT campaign_id FROM membership WHERE domain=? LIMIT 1", (mine,)).fetchone()
        if row:
            campaign_id = row[0]
        else:
            member_ids = [r[0] for r in conn.execute(
                "SELECT DISTINCT campaign_id FROM membership WHERE domain IN (%s)"
                % ",".join("?" * len(members)), members)] if members else []
            if member_ids:
                campaign_id = min(member_ids)
            else:
                cur = conn.execute("INSERT INTO membership(campaign_id,domain) VALUES(0,?)",
                                   (mine,))
                campaign_id = cur.lastrowid
        conn.execute(
            "INSERT OR IGNORE INTO membership(campaign_id,domain) VALUES(?,?)",
            (campaign_id, mine))
        for m in members:
            conn.execute(
                "INSERT OR IGNORE INTO membership(campaign_id,domain) VALUES(?,?)",
                (campaign_id, m))
        conn.commit()

    inherited = 0
    already_flagged = (any(t.listed for t in report.threat_intel)
                       or report.visual_matches
                       or any(h.weight >= 15 for h in report.heuristics))
    if bad_members and not already_flagged:
        share = len(bad_members) / max(1, len(members))
        inherited = min(CAMPAIGN_INHERIT_CAP,
                        int(round(CAMPAIGN_INHERIT_WEIGHT * (0.5 + share))))

    summary_bits = [f"{len(members)} related domain(s)", f"{len(bad_members)} flagged"]
    if shared:
        summary_bits.append(f"shared: {', '.join(shared[:3])}")
    return CampaignMatch(
        campaign_id=campaign_id,
        member_count=len(members),
        bad_member_count=len(bad_members),
        shared_keys=shared[:20],
        inherited_points=inherited,
        summary=f"Campaign #{campaign_id}: " + "; ".join(summary_bits),
    )
