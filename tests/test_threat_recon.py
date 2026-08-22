"""
tests/test_threat_recon.py — Unit tests (note to self).

Offline tests for core logic: heuristics, risk scoring, diffs and hashing.
Run with `python -m unittest` or `pytest` if you prefer.
"""

from __future__ import annotations

import datetime as dt
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import (  # noqa: E402
    CveRecord, DomainIntel, HeuristicHit, IngestedPage, MisconfigFinding,
    ScanReport, SecurityFinding, ThreatIntelHit, VisualMatch,
)
from modules.recon import heuristics, intel, risk, security_headers, visual  # noqa: E402
from modules import evidence, store  # noqa: E402


def _page(dom="", url="https://x.test/", headers=None, shot=None):
    return IngestedPage(final_url=url, http_status=200,
                        response_headers=headers or {}, dom_html=dom,
                        screenshot_path=shot, rendered=True)


def _report(**kw):
    r = ScanReport(target_url=kw.get("url", "https://x.test/"),
                   timestamp_utc="2026-06-26T00:00:00Z")
    for k, v in kw.items():
        if k != "url":
            setattr(r, k, v)
    return r


class TestRiskDiscrimination(unittest.TestCase):
    def test_clean_page_is_clean(self):
        r = _report()
        r.risk = risk.assess_risk(r)
        self.assertEqual(r.risk.level, "Clean")
        self.assertEqual(r.risk.score, 0)

    def test_blatant_scam_outranks_mild(self):
        mild = _report(heuristics=[HeuristicHit(category="scam_urgency",
                       detail="x", severity="low", weight=4)])
        blatant = _report(heuristics=[
            HeuristicHit(category="scam_investment", detail="x", severity="high", weight=14),
            HeuristicHit(category="brand_impersonation", detail="x", severity="high", weight=16),
            HeuristicHit(category="fake_gateway", detail="x", severity="high", weight=14),
            HeuristicHit(category="credential_harvest", detail="x", severity="high", weight=14)],
            misconfigs=[MisconfigFinding(path="/.env", http_status=200, exposed=True,
                                         category="secrets", severity="critical")])
        mild.risk = risk.assess_risk(mild)
        blatant.risk = risk.assess_risk(blatant)
        self.assertLess(mild.risk.score, blatant.risk.score)
        self.assertIn(mild.risk.level, ("Clean", "Low"))

    def test_volume_does_not_saturate(self):
        # 30 identical weak phrases must NOT reach Critical (diminishing returns).
        many = _report(heuristics=[HeuristicHit(category="scam_urgency", detail=f"{i}",
                       evidence=f"e{i}", severity="low", weight=4) for i in range(30)])
        many.risk = risk.assess_risk(many)
        self.assertNotEqual(many.risk.level, "Critical")

    def test_threat_feed_listing_raises_score(self):
        base = _report(heuristics=[HeuristicHit(category="scam_reward", detail="x",
                       severity="medium", weight=8)])
        listed = _report(heuristics=list(base.heuristics),
                         threat_intel=[ThreatIntelHit(source="URLhaus", listed=True,
                                                      detail="listed")])
        base.risk = risk.assess_risk(base)
        listed.risk = risk.assess_risk(listed)
        self.assertGreater(listed.risk.score, base.risk.score)

    def test_young_domain_adds_risk(self):
        old = _report(intel=DomainIntel(domain="x.test", age_days=2000))
        young = _report(intel=DomainIntel(domain="x.test", age_days=3))
        old.risk = risk.assess_risk(old)
        young.risk = risk.assess_risk(young)
        self.assertGreater(young.risk.score, old.risk.score)


class TestScamHeuristics(unittest.TestCase):
    def test_multitype_and_brand_wordboundary(self):
        dom = ("Double your money! Work from home, earn daily. "
               "<form><input type=password name=mpin></form> gcash promo")
        hits = heuristics.analyze_heuristics(_page(dom=dom, url="https://promo.example/"))
        cats = {h.category for h in hits}
        self.assertIn("scam_investment", cats)
        self.assertIn("scam_job", cats)
        self.assertIn("credential_harvest", cats)
        self.assertIn("brand_impersonation", cats)  # 'gcash' off official domain

    def test_brand_substring_does_not_false_positive(self):
        # 'maya' as a plain word elsewhere should not, by itself, be impersonation
        # unless the word-boundary brand token genuinely appears. Here 'mayabird'
        # must NOT match the 'maya' brand.
        hits = heuristics.analyze_heuristics(_page(dom="the mayabird flew", url="https://b.example/"))
        self.assertFalse(any(h.category == "brand_impersonation" for h in hits))

    def test_url_anomaly_at_sign(self):
        hits = heuristics.analyze_heuristics(_page(dom="hello", url="https://bank.com@evil.test/login"))
        self.assertTrue(any(h.category == "url_anomaly" for h in hits))


class TestSecurityExposure(unittest.TestCase):
    def test_secret_and_cors_and_form(self):
        dom = ('<script>var k="AKIAIOSFODNN7EXAMPLE";</script>'
               '<form action="http://evil.test/c.php"><input type=password></form>')
        headers = {"access-control-allow-origin": "*",
                   "access-control-allow-credentials": "true",
                   "set-cookie": "PHPSESSID=abc; path=/"}
        sf = security_headers.audit_security(_page(dom=dom, headers=headers))
        cats = {s.category for s in sf}
        self.assertIn("sensitive_exposure", cats)
        self.assertIn("cors", cats)
        self.assertIn("insecure_form", cats)
        self.assertIn("weak_cookie", cats)

    def test_secret_is_redacted(self):
        dom = '<script>var k="AKIAIOSFODNN7EXAMPLE";</script>'
        sf = security_headers.audit_security(_page(dom=dom))
        secret = next(s for s in sf if s.category == "sensitive_exposure")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", secret.evidence)  # masked


class TestIntelParsing(unittest.TestCase):
    def test_registrable_domain(self):
        self.assertEqual(intel.registrable_domain("www.shop.scam.com.ph"), "scam.com.ph")
        self.assertEqual(intel.registrable_domain("a.b.example.com"), "example.com")

    def test_age_days(self):
        now = dt.datetime(2026, 6, 26, tzinfo=dt.timezone.utc)
        self.assertEqual(intel.age_days("2026-06-16T00:00:00Z", now=now), 10)
        self.assertIsNone(intel.age_days(None))

    def test_parse_domain_rdap(self):
        sample = {
            "events": [{"eventAction": "registration", "eventDate": "2026-06-01T00:00:00Z"}],
            "entities": [{
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "EvilRegistrar Inc"]]],
                "entities": [{"roles": ["abuse"],
                              "vcardArray": ["vcard", [["email", {}, "text", "abuse@reg.test"]]]}],
            }],
            "nameservers": [{"ldhName": "NS1.REG.TEST"}],
        }
        out = intel.parse_domain_rdap(sample)
        self.assertEqual(out["registrar"], "EvilRegistrar Inc")
        self.assertEqual(out["registrar_abuse_email"], "abuse@reg.test")
        self.assertEqual(out["creation_date"], "2026-06-01T00:00:00Z")
        self.assertIn("ns1.reg.test", out["nameservers"])


class TestVisualHash(unittest.TestCase):
    def test_dhash_and_hamming(self):
        from PIL import Image
        with tempfile.TemporaryDirectory() as d:
            a = os.path.join(d, "a.png")
            b = os.path.join(d, "b.png")
            img = Image.new("L", (64, 64), 0)
            for x in range(64):
                for y in range(64):
                    img.putpixel((x, y), (x * 4) % 256)
            img.save(a)
            img.save(b)
            ha, hb = visual.dhash(a), visual.dhash(b)
            self.assertIsNotNone(ha)
            self.assertEqual(visual.hamming(ha, hb), 0)  # identical images
            self.assertEqual(visual.hamming(ha, ~ha & ((1 << 64) - 1)), 64)


class TestStoreDiff(unittest.TestCase):
    def test_diff_detects_changes(self):
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "c.db")
            r1 = _report(url="https://t.test/", risk=None,
                         misconfigs=[MisconfigFinding(path="/.env", http_status=200,
                                     exposed=True, category="secrets", severity="critical")])
            r1.risk = risk.assess_risk(r1)
            self.assertIn("First recorded", store.diff_against_previous(r1, db)[0])
            store.save_scan(r1, db)
            # second scan: add a new exposed path
            r2 = _report(url="https://t.test/",
                         misconfigs=list(r1.misconfigs) + [MisconfigFinding(
                             path="/.git/config", http_status=200, exposed=True,
                             category="source_control", severity="high")])
            r2.risk = risk.assess_risk(r2)
            diff = store.diff_against_previous(r2, db)
            self.assertTrue(any(".git/config" in line for line in diff))
            self.assertEqual(len(store.history("https://t.test/", db)), 1)


class TestEvidence(unittest.TestCase):
    def test_hash_and_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "evidence.txt")
            with open(f, "w") as fh:
                fh.write("hello")
            digest = evidence.sha256_file(f)
            # sha256("hello")
            self.assertEqual(digest,
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
            hashes = evidence.hash_files([f])
            mpath = evidence.write_manifest(d, "https://t.test/", "2026-06-26T00:00:00Z", hashes)
            self.assertTrue(os.path.exists(mpath))


if __name__ == "__main__":
    unittest.main(verbosity=2)