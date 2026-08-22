# Knowledge folder — JSON schema reference

All files live in `knowledge/` next to `knowledge_loader.py` by default.
Override the location with the `HEURISTICS_KNOWLEDGE_DIR` environment
variable, or by passing `knowledge_dir="/some/path"` to the `load_*`
functions.

Matching is always case-insensitive; you do not need to lowercase phrases
yourself (the loader does it), but for regex `pattern` strings you may set
`"ignore_case": false` if you need case-sensitive matching.

---

## `lexicon.json`

Plain-substring scam phrases (English/Tagalog/Taglish/etc).

```jsonc
{
  "entries": [
    {
      "category": "investment",   // string — scam type, shown in reports
      "phrase": "double your money", // string — substring match, case-insensitive
      "severity": "high",         // "low" | "medium" | "high"
      "weight": 12                // int — contributes to the risk score
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
  "entries": [
    {
      "category": "fake_gateway",     // string — signal group
      "label": "Telegram bot-API payment/exfil endpoint", // human-readable name
      "severity": "high",             // "low" | "medium" | "high"
      "weight": 14,                   // int
      "pattern": "api\\.telegram\\.org/bot[\\w:-]+", // Python regex, as a JSON string
      "ignore_case": true             // optional, default true
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
  "entries": [
    {
      "label": "eval(atob(...)) base64 execution", // human-readable name
      "pattern": "eval\\s*\\(\\s*atob\\s*\\(",       // Python regex string
      "ignore_case": true                            // optional, default true
    }
  ]
}
```

Every hit is reported at a fixed `severity: "medium"`, `weight: 7` (set in
`heuristics.py`); this file only supplies the label + pattern.

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