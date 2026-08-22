"""One-shot migration: add rule envelope (id/version/source/confidence/enabled/
created/updated) to every knowledge JSON entry. Run once, then delete."""

import json
import re
import sys
from pathlib import Path

KNOWLEDGE = Path(__file__).resolve().parent / "modules" / "recon" / "knowledge"
TODAY = "2026-08-22"
KV = "2026.08.22.1"


def slug(s):
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return s[:60]


def envelope(prefix, i, e, source="curated", confidence=0.8):
    name = e.get("phrase") or e.get("label") or e.get("cookie_name") or \
        e.get("product") or e.get("path") or e.get("header_name") or f"{i}"
    rid = e.get("id") or f"{prefix}.{slug(name)}"
    out = dict(e)
    out["id"] = rid
    out["version"] = 1
    out["source"] = source
    out["confidence"] = confidence
    out["enabled"] = True
    out["created"] = TODAY
    out["updated"] = TODAY
    return out


def migrate(fname, prefix, confidence=0.8, top=None):
    p = KNOWLEDGE / fname
    data = json.loads(p.read_text(encoding="utf-8"))
    if "entries" not in data:
        entries = [{"id": f"{prefix}.{slug(k)}", **v} if isinstance(v, dict) else v
                   for k, v in []]
        data = {"entries": data} if isinstance(data, list) else None
        if data is None:
            # reference.json style: flat object of lists -> keep as-is but wrap
            return
    wrapped = isinstance(data, dict) and "entries" in data
    raw_entries = data["entries"]
    new_entries = [envelope(prefix, i, e, confidence=confidence)
                   for i, e in enumerate(raw_entries)]
    doc = {"schema_version": 1, "knowledge_version": KV, "entries": new_entries}
    p.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{fname}: {len(new_entries)} entries migrated")


# lexicon / regex / obfuscation are {"entries": [...]}
migrate("lexicon.json", "lex", confidence=0.85)
migrate("regex_detectors.json", "regex", confidence=0.8)
migrate("obfuscation_patterns.json", "obf", confidence=0.7)

# reference.json is a flat object of lists — wrap it with version headers,
# keep its shape (it's a lookup bundle, not scored rules; no per-entry envelope).
ref_path = KNOWLEDGE / "reference.json"
ref = json.loads(ref_path.read_text(encoding="utf-8"))
ref_doc = {"schema_version": 1, "knowledge_version": KV, **ref}
ref_path.write_text(json.dumps(ref_doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print("reference.json: wrapped with schema/knowledge_version")

print("done")
