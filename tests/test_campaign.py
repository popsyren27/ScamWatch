import sqlite3

from models import CampaignMatch, DomainIntel, HeuristicHit, RiskAssessment, ScanReport, ThreatIntelHit
from modules.recon.campaign import _components, _edges, correlate_campaign


def _report(domain, favicon=None, wallet=None, risk_level="Low", listed=False):
    intel = DomainIntel(domain=domain, favicon_hash=favicon)
    return ScanReport(
        target_url=f"https://{domain}/",
        timestamp_utc="2026-08-23T00:00:00Z",
        intel=intel,
        threat_intel=[ThreatIntelHit(source="URLhaus", listed=listed)],
        risk=RiskAssessment(score=90 if listed else 5, level=risk_level, summary=""),
    )


def test_components_union_on_strong_key():
    obs = {
        "a.com": [("favicon", "h1")],
        "b.com": [("favicon", "h1")],
        "c.com": [("favicon", "h2")],
    }
    comps = _components(set(obs), _edges(obs))
    joined = next(c for c in comps if "a.com" in c)
    assert "b.com" in joined and "c.com" not in joined


def test_weak_hosting_key_does_not_cluster():
    obs = {
        "a.com": [("hosting", "cloudflare")],
        "b.com": [("hosting", "cloudflare")],
    }
    assert _edges(obs) == []


def test_two_medium_keys_cluster():
    obs = {
        "a.com": [("analytics", "g-abc"), ("js_asset", "cdn/x.js")],
        "b.com": [("analytics", "g-abc"), ("js_asset", "cdn/x.js")],
    }
    assert len(_edges(obs)) == 1


def test_correlate_inherits_from_bad_campaign(tmp_path):
    db = str(tmp_path / "camp.db")
    bad = _report("known-bad.com", favicon="deadbeef", listed=True)
    correlate_campaign(bad, db)

    fresh = _report("brand-new.com", favicon="deadbeef")
    match = correlate_campaign(fresh, db)

    assert match is not None
    assert match.member_count == 1
    assert match.bad_member_count == 1
    assert match.inherited_points > 0
    assert any("favicon" in k for k in match.shared_keys)


def test_clean_campaign_no_inheritance(tmp_path):
    db = str(tmp_path / "camp.db")
    correlate_campaign(_report("clean-a.com", favicon="aa"), db)
    match = correlate_campaign(_report("clean-b.com", favicon="aa"), db)
    assert match.bad_member_count == 0
    assert match.inherited_points == 0


def test_already_flagged_domain_does_not_double_inherit(tmp_path):
    db = str(tmp_path / "camp.db")
    correlate_campaign(_report("bad.com", favicon="bb", listed=True), db)
    match = correlate_campaign(
        _report("new.com", favicon="bb", listed=True, risk_level="Critical"), db)
    assert match.inherited_points == 0
