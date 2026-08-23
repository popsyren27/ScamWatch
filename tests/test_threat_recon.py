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
from modules.recon import fuzzy_lexical  # noqa: E402
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


class TestFuzzyLexical(unittest.TestCase):
    def test_normalize_folds_homoglyphs_and_punct(self):
        from modules.recon.fuzzy_lexical import normalize_text
        self.assertEqual(normalize_text("Guаranteed   Returns!!"), "guaranteed returns")
        self.assertEqual(normalize_text("ｌｉｂｒｅｎｇ ｐｅｒａ"), "libreng pera")

    def test_exact_soft_phrase_matches(self):
        hits = fuzzy_lexical.scan_fuzzy_phrases("<p>Get guaranteed returns today!</p>")
        self.assertTrue(any(h.rule_id == "soft.en.investment-returns" for h in hits))

    def test_homoglyph_evasion_still_matches(self):
        # Cyrillic 'а' in "guaranteed"
        dom = "G\u0443aranteed returns for everyone"
        hits = fuzzy_lexical.scan_fuzzy_phrases(dom)
        self.assertTrue(any(h.rule_id == "soft.en.investment-returns" for h in hits))

    def test_fuzzy_variant_matches(self):
        hits = fuzzy_lexical.scan_fuzzy_phrases("<p>guaranteed returnss now</p>")
        self.assertTrue(any(h.rule_id == "soft.en.investment-returns" for h in hits))

    def test_benign_text_no_match(self):
        hits = fuzzy_lexical.scan_fuzzy_phrases("<p>Quarterly earnings report and dividend policy.</p>")
        self.assertEqual(hits, [])

    def test_fuzzy_hits_scored_below_exact(self):
        exact = _report(heuristics=[HeuristicHit(category="scam_investment", detail="x",
                        severity="high", weight=14)])
        fuzzy = _report(heuristics=[HeuristicHit(category="scam_phrase_fuzzy", detail="x",
                        severity="low", weight=7)])
        exact.risk = risk.assess_risk(exact)
        fuzzy.risk = risk.assess_risk(fuzzy)
        self.assertLess(fuzzy.risk.score, exact.risk.score)


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


class TestKnowledgeSchema(unittest.TestCase):
    def test_all_knowledge_files_load_and_validate(self):
        from modules.recon import knowledge_loader as kb
        self.assertTrue(len(kb.load_lexicon()) > 0)
        self.assertTrue(len(kb.load_regex_detectors()) > 0)
        self.assertTrue(len(kb.load_obfuscation_patterns()) > 0)
        self.assertTrue(len(kb.load_revealing_headers()) > 0)
        self.assertTrue(len(kb.load_cookie_signatures()) > 0)
        self.assertTrue(len(kb.load_dom_signatures()) > 0)
        self.assertTrue(len(kb.load_js_lib_patterns()) > 0)
        self.assertTrue(len(kb.load_misconfig_targets()) > 0)
        self.assertTrue(len(kb.load_security_headers_expected()) > 0)

    def test_knowledge_version_is_stamped(self):
        from modules.recon import knowledge_loader as kb
        kv = kb.get_knowledge_version()
        self.assertNotEqual(kv, "unknown")
        self.assertIn("2026.08.22.1", kv)

    def test_malformed_entry_raises_with_context(self):
        from modules.recon import knowledge_loader as kb
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "lexicon.json")
            with open(bad, "w", encoding="utf-8") as fh:
                fh.write('{"schema_version": 1, "knowledge_version": "t", "entries": '
                         '[{"category": "x", "phrase": "y", "severity": "high", '
                         '"weight": 5, "bogus_field": 1}]}')
            with self.assertRaises(ValueError) as ctx:
                kb.load_lexicon(d)
            self.assertIn("failed schema validation", str(ctx.exception))

    def test_duplicate_rule_id_rejected(self):
        from modules.recon import knowledge_loader as kb
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "lexicon.json")
            entry = ('{"id": "lex.dup", "category": "x", "phrase": "y", '
                     '"severity": "high", "weight": 5}')
            with open(bad, "w", encoding="utf-8") as fh:
                fh.write('{"schema_version": 1, "knowledge_version": "t", '
                         '"entries": [' + entry + ',' + entry + ']}')
            with self.assertRaises(ValueError) as ctx:
                kb.load_lexicon(d)
            self.assertIn("duplicate rule id", str(ctx.exception))

    def test_disabled_rule_never_fires(self):
        from modules.recon import knowledge_loader as kb
        with tempfile.TemporaryDirectory() as d:
            lex = os.path.join(d, "lexicon.json")
            with open(lex, "w", encoding="utf-8") as fh:
                fh.write('{"schema_version": 1, "knowledge_version": "t", "entries": ['
                         '{"id": "lex.on", "category": "urgency", "phrase": "act now", '
                         '"severity": "low", "weight": 4, "enabled": true},'
                         '{"id": "lex.off", "category": "payment", "phrase": "activation fee", '
                         '"severity": "high", "weight": 12, "enabled": false}]}')
            kb.clear_cache()
            os.environ["HEURISTICS_KNOWLEDGE_DIR"] = d
            try:
                hits = heuristics.analyze_heuristics(_page(dom="act now! activation fee!"))
                cats = {h.rule_id for h in hits}
                self.assertIn("lex.on", cats)
                self.assertNotIn("lex.off", cats)
            finally:
                kb.clear_cache()
                del os.environ["HEURISTICS_KNOWLEDGE_DIR"]

    def test_hits_carry_rule_ids(self):
        dom = "double your money today"
        hits = heuristics.analyze_heuristics(_page(dom=dom))
        lex_hits = [h for h in hits if h.category == "scam_investment"]
        self.assertTrue(lex_hits)
        self.assertTrue(all(h.rule_id and h.rule_id.startswith("lex.") for h in lex_hits))

    def test_techstack_uses_json_signatures(self):
        from modules.recon import techstack
        page = _page(dom='<meta name="generator" content="WordPress 5.2">'
                         '<script src="/wp-content/themes/x.js"></script>'
                         'jquery-3.4.1.min.js',
                     headers={"Server": "nginx/1.14.0",
                              "Set-Cookie": "PHPSESSID=abc; wordpress_logged_in=xyz"})
        fps = techstack.map_tech_stack(page)
        by_product = {f.product: f for f in fps}
        self.assertIn("nginx", by_product)
        self.assertIn("WordPress", by_product)
        self.assertIn("PHP", by_product)  # canonical casing from the JSON rule
        self.assertTrue(all(f.rule_id for f in fps))


if __name__ == "__main__":
    unittest.main(verbosity=2)