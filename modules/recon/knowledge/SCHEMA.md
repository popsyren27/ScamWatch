# Knowledge folder — JSON schema reference

All files live in `knowledge/` next to `knowledge_loader.py` by default.
Override the location with the `HEURISTICS_KNOWLEDGE_DIR` environment
variable, or by passing `knowledge_dir="/some/path"` to the `load_*`
functions.

Matching is always case-insensitive; you do not need to lowercase phrases
yourself (the loader does it), but for regex `pattern` strings you may set
`"ignore_case": false` if you need case-sensitive matching.

---

## Rule envelope (all scored rules)

Every entry in `lexicon.json`, `regex_detectors.json`,
`obfuscation_patterns.json`, `tech_signatures.json` and
`posture_targets.json` carries an identity envelope, validated on load by
pydantic models in `knowledge_schema.py` (unknown fields are rejected,
duplicate ids are rejected, malformed entries raise with file + index):

```jsonc
{
  "id": "lex.double-your-money", // REQUIRED, unique within the file
  "version": 1,                  // rule revision, bump when meaning changes
  "source": "curated",           // where the rule came from
  "confidence": 0.85,            // 0.0-1.0 analyst confidence
  "enabled": true,               // false = rule never fires
  "created": "2026-08-22",
  "updated": "2026-08-22"
}
```

Every fired `HeuristicHit` / `TechFingerprint` records the `rule_id` that
produced it, so per-rule performance can be measured later.

## File wrapper

Scored files are wrapped as:

```jsonc
{
  "schema_version": 1,
  "knowledge_version": "2026.08.22.1",  // bump on any content change
  "entries": [ ... ]
}
```

`get_knowledge_version()` joins the per-file versions and the aggregate is
stamped onto every `ScanReport.knowledge_version` so an old verdict can be
reproduced/explained after the knowledge base evolves.

`reference.json` keeps its flat lookup-list shape but also carries
`schema_version` + `knowledge_version`.

---

## `lexicon.json`

Plain-substring scam phrases (English/Tagalog/Taglish/etc).

```jsonc
{
  "schema_version": 1,
  "knowledge_version": "2026.08.22.1",
  "entries": [
    {
      "id": "lex.double-your-money",   // unique rule id
      "category": "investment",        // string — scam type, shown in reports
      "phrase": "double your money",   // substring match, case-insensitive
      "severity": "high",              // info|low|medium|high|critical
      "weight": 12,                    // int — contributes to the risk score
      "...envelope...": "see above"
    }
  ]
}
```

---

## `regex_detectors.json`

Structural signals matched with a compiled regular expression against the
raw page HTML (URLs, wallet addresses, off-platform contact links, etc).

```jsonc
{
  "schema_version": 1,
  "knowledge_version": "2026.08.22.1",
  "entries": [
    {
      "id": "regex.telegram-bot-api",
      "category": "fake_gateway",     // string — signal group
      "label": "Telegram bot-API payment/exfil endpoint", // human-readable name
      "severity": "high",             // info|low|medium|high|critical
      "weight": 14,                   // int
      "pattern": "api\\.telegram\\.org/bot[\\w:-]+", // Python regex, as a JSON string
      "ignore_case": true,            // optional, default true
      "...envelope...": "see above"
    }
  ]
}
```

Notes:
- `pattern` is compiled with `re.compile`, so any valid Python regex syntax
  works. Remember JSON strings need `\\` for a literal backslash.
- Matches are captured with `pattern.findall(html)`, so a pattern with
  capturing groups changes what gets recorded as evidence — prefer
  non-capturing groups `(?:...)` unless you specifically want a group's text
  as the evidence string.

---

## `obfuscation_patterns.json`

Regexes that flag obfuscated/packed JavaScript.

```jsonc
{
  "schema_version": 1,
  "knowledge_version": "2026.08.22.1",
  "entries": [
    {
      "id": "obf.eval-atob",
      "label": "eval(atob(...)) base64 execution", // human-readable name
      "pattern": "eval\\s*\\(\\s*atob\\s*\\(",       // Python regex string
      "ignore_case": true,                           // optional, default true
      "...envelope...": "see above"
    }
  ]
}
```

Every hit is reported at a fixed `severity: "medium"`, `weight: 7` (set in
`heuristics.py`); this file only supplies the label + pattern.

---

## `tech_signatures.json`

Tech-stack fingerprinting rules (moved out of `techstack.py`). Four arrays:

- `revealing_headers`: `{ id, header_name }` — headers parsed for product/version.
- `cookie_signatures`: `{ id, cookie_name, product }` — Set-Cookie name → backend product.
- `dom_signatures`: `{ id, product, pattern, ignore_case? }` — DOM asset-path regex → CMS/framework.
- `js_lib_patterns`: `{ id, products: [...], pattern, ignore_case? }` — versioned JS-lib filename regex.

All wrapped in the same `schema_version` / `knowledge_version` object.

---

## `posture_targets.json`

Passive posture-probe rules (moved out of `config.py`). Two arrays:

- `misconfig_targets`: `{ id, path, category, severity }` — sensitive paths probed
  (status only; bodies never downloaded).
- `security_headers_expected`: `{ id, header_name, severity_if_missing, explanation }` —
  headers a well-configured site should send.

---

## `reference.json`

Flat lookup lists (not scored rules, so no per-entry envelope):
`currency_markers`, `ph_brands`, `brand_official_domains`, `suspicious_tlds`,
`credential_hints`, `high_severity_credential_hints`, `phishy_path_words`.
Carries `schema_version` + `knowledge_version` at the top level.

---

## `reference.json`

Small flat lists used for brand-impersonation checks, domain-reputation
checks, credential-field checks, and URL path checks. All entries are plain
strings (case-insensitive).

```jsonc
{
  "currency_markers": ["₱", "php ", "pesos"],
  // Soft contextual cue that the page is PH-currency related.

  "ph_brands": ["gcash", "maya", "bpi"],
  // Brand names to detect (word-boundary matched) when mentioned off their
  // official domain. Each becomes an auto-compiled \bword\b pattern.

  "brand_official_domains": ["gcash.com", "bpi.com.ph"],
  // A brand mention is NOT flagged if the page's host is one of these
  // domains or a subdomain of one.

  "suspicious_tlds": [".xyz", ".top", ".tk"],
  // TLDs that trigger a low-weight "domain_reputation" hit.
  // Include the leading dot.

  "credential_hints": ["otp", "cvv", "password", "card number"],
  // Substrings looked for in <input> type/name/id/placeholder/aria-label
  // attributes (and as a raw-HTML fallback if BeautifulSoup isn't installed).

  "high_severity_credential_hints": ["mpin", "otp", "cvv", "atm pin"],
  // Subset of credential_hints that should score "high"/14 instead of
  // "medium"/8 when found. Must also appear in credential_hints.

  "phishy_path_words": ["login", "verify", "secure", "account"]
  // Path keywords that, on a non-official host, suggest a phishing
  // landing page.
}
```