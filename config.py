"""
config.py — App-wide constants (my brain dump).

All the knobs live here. I like using `Final` so I don't accidentally rebind
things elsewhere. Edit these values when tuning behaviour or running locally.

TODO:
- Consider splitting local dev overrides into a `config_local.py` ignored by VCS.
"""

from __future__ import annotations

from typing import Dict, Final, Tuple

# --------------------------------------------------------------------------
# Phase 1 — Anonymity & Network Layer
# --------------------------------------------------------------------------
# Stock Tor Browser / system-tor defaults — change here only if your Tor
# daemon listens elsewhere.
TOR_SOCKS_HOST: Final[str] = "127.0.0.1"
TOR_SOCKS_PORT: Final[int] = 9050
TOR_CONTROL_PORT: Final[int] = 9051
# Control-port password. Empty string => cookie auth / no password.
TOR_CONTROL_PASSWORD: Final[str] = ""

# SOCKS5h resolves DNS *through* Tor (the trailing 'h'), preventing DNS leaks
# that would otherwise expose the host's browsing to its own resolver.
TOR_PROXY_URL: Final[str] = f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}"

# External services used to confirm the exit IP differs from the host IP.
# Multiple independent providers so a single outage can't blind the leak check.
IP_ECHO_SERVICES: Final[Tuple[str, ...]] = (
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
)

# Seconds to wait for a freshly-signalled Tor circuit to become usable.
TOR_NEWNYM_SETTLE_SECONDS: Final[float] = 5.0

# --------------------------------------------------------------------------
# Phase 2 — Data Ingestion Engine
# --------------------------------------------------------------------------
# Hard ceiling per page interaction — defends against tarpits and infinite
# redirect chains designed to hang scanners.
PAGE_TIMEOUT_MS: Final[int] = 15_000
NAV_TIMEOUT_MS: Final[int] = 15_000

# A benign, common desktop UA. We're passive observers — this isn't to evade
# detection, just to receive the same DOM a normal visitor would.
USER_AGENT: Final[str] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# Where evidence (screenshots, reports) is written.
ARTIFACT_DIR: Final[str] = "artifacts"

# --------------------------------------------------------------------------
# Phase 3 — Passive Recon
# --------------------------------------------------------------------------
# NVD (National Vulnerability Database) 2.0 API. An API key is optional but
# lifts the rate limit; leave blank to use the slower anonymous tier.
NVD_API_BASE: Final[str] = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY: Final[str] = ""
NVD_MAX_CVES_PER_PRODUCT: Final[int] = 10

# Paths probed for misconfiguration — only HTTP status is read, bodies are
# never downloaded or parsed. Each target is (path, category, severity);
# severity feeds the risk score, category groups the finding in the report.
MISCONFIG_TARGETS: Final[Tuple[Tuple[str, str, str], ...]] = (
    # --- Source-control exposure (frequently leaks full source + secrets) ---
    ("/.git/config", "source_control", "high"),
    ("/.git/HEAD", "source_control", "high"),
    ("/.git/index", "source_control", "high"),
    ("/.git/logs/HEAD", "source_control", "high"),
    ("/.svn/entries", "source_control", "high"),
    ("/.svn/wc.db", "source_control", "high"),
    ("/.hg/store/00manifest.i", "source_control", "high"),
    ("/.bzr/branch/branch.conf", "source_control", "medium"),
    # --- Secrets / environment files ---
    ("/.env", "secrets", "critical"),
    ("/.env.local", "secrets", "critical"),
    ("/.env.production", "secrets", "critical"),
    ("/.env.bak", "secrets", "critical"),
    ("/.aws/credentials", "secrets", "critical"),
    ("/.htpasswd", "secrets", "high"),
    ("/.netrc", "secrets", "high"),
    ("/.npmrc", "secrets", "medium"),
    ("/secrets.json", "secrets", "high"),
    ("/credentials.json", "secrets", "high"),
    # --- Backups / database dumps ---
    ("/backup.sql", "backup", "high"),
    ("/database.sql", "backup", "high"),
    ("/dump.sql", "backup", "high"),
    ("/backup.zip", "backup", "high"),
    ("/site.tar.gz", "backup", "high"),
    ("/config.php.bak", "backup", "high"),
    ("/wp-config.php.bak", "backup", "critical"),
    ("/.DS_Store", "backup", "low"),
    # --- Framework / application config & logs ---
    ("/config.json", "config", "medium"),
    ("/composer.json", "config", "low"),
    ("/composer.lock", "config", "low"),
    ("/package.json", "config", "low"),
    ("/web.config", "config", "medium"),
    ("/wp-config.php", "config", "medium"),
    ("/storage/logs/laravel.log", "logs", "high"),
    # --- Debug / information-disclosure endpoints ---
    ("/phpinfo.php", "info_disclosure", "high"),
    ("/info.php", "info_disclosure", "high"),
    ("/server-status", "info_disclosure", "medium"),
    ("/server-info", "info_disclosure", "medium"),
    ("/actuator/health", "info_disclosure", "medium"),
    ("/actuator/env", "info_disclosure", "high"),
    ("/debug", "info_disclosure", "medium"),
    # --- Exposed admin surfaces ---
    ("/adminer.php", "admin", "medium"),
    ("/phpmyadmin/", "admin", "medium"),
)

# Backward-compatible flat path tuple, derived from the structured targets.
MISCONFIG_PATHS: Final[Tuple[str, ...]] = tuple(t[0] for t in MISCONFIG_TARGETS)

# Map of path -> (category, severity) for O(1) enrichment of a probe result.
MISCONFIG_META: Final[Dict[str, Tuple[str, str]]] = {
    path: (category, severity) for path, category, severity in MISCONFIG_TARGETS
}

# --- Soft-404 / catch-all baseline guard ----------------------------------
# Many sites (SPAs, parked domains, soft-404 handlers) answer HTTP 200 to ANY
# path. Before the sweep we probe a couple of certainly-nonexistent paths; if
# they also return 200, the host is a catch-all and every probe result gets
# treated as inconclusive instead of a phantom "exposed" finding.
CATCHALL_PROBE_PATHS: Final[Tuple[str, ...]] = (
    "/threatrecon-baseline-9f3a2b7c1e.nonexistent",
    "/__does_not_exist__/a8d4f60b.html",
)

# --------------------------------------------------------------------------
# Phase 3 — Passive web-security posture audit
# --------------------------------------------------------------------------
# Response headers a well-configured site is expected to send. A missing header
# is recorded as a (defensive) finding and contributes to the risk score. Each
# entry: (header_name_lowercase, severity_if_missing, human_explanation).
SECURITY_HEADERS_EXPECTED: Final[Tuple[Tuple[str, str, str], ...]] = (
    ("content-security-policy", "medium",
     "No Content-Security-Policy — nothing constrains injected scripts or framing."),
    ("strict-transport-security", "medium",
     "No HSTS — connections can be silently downgraded to plaintext HTTP (MITM)."),
    ("x-frame-options", "low",
     "No X-Frame-Options — the page can be framed for clickjacking."),
    ("x-content-type-options", "low",
     "No 'X-Content-Type-Options: nosniff' — MIME-sniffing attacks are possible."),
    ("referrer-policy", "info",
     "No Referrer-Policy — full URLs may leak to third-party destinations."),
    ("permissions-policy", "info",
     "No Permissions-Policy — powerful browser features are left unrestricted."),
)

# --------------------------------------------------------------------------
# Phase 3 — Risk synthesis (aggregate scoring)
# --------------------------------------------------------------------------
# Points contributed per finding, by severity band. Scam heuristics carry their
# own per-hit weight; these map the severity labels used by CVE, misconfig and
# security-posture findings onto a common point scale.
RISK_SEVERITY_WEIGHTS: Final[Dict[str, int]] = {
    "info": 1,
    "low": 4,
    "medium": 10,
    "high": 20,
    "critical": 35,
}

# Final score (0-100, capped) -> verdict band. Ordered ascending; the highest
# threshold a score meets or exceeds wins. Tune the cut-offs here only.
RISK_BANDS: Final[Tuple[Tuple[int, str], ...]] = (
    (0, "Clean"),
    (10, "Low"),
    (30, "Medium"),
    (55, "High"),
    (80, "Critical"),
)

# Findings roll up by bucket with diminishing returns (the Nth finding of a
# kind is worth decay**N of its weight), then the bucket total is capped. This
# stops "20 weak scam phrases" from saturating the score on its own, so 0-100
# actually discriminates between a borderline page and a blatant one.
RISK_DECAY: Final[float] = 0.6
RISK_CATEGORY_CAPS: Final[Dict[str, int]] = {
    "scam": 55,       # all scam heuristics combined
    "cve": 45,        # known CVEs in the stack
    "misconfig": 45,  # exposed sensitive paths
    "posture": 25,    # weak/missing security controls (headers, cookies, CORS…)
    "exposure": 40,   # secrets / sensitive data leaked into the page
}

# --------------------------------------------------------------------------
# Phase 3 — Domain & hosting intelligence (RDAP / CT logs)
# --------------------------------------------------------------------------
# RDAP is the modern JSON successor to WHOIS and is HTTP-based, so it routes
# cleanly through Tor (port-43 WHOIS would leak). rdap.org bootstraps to the
# correct registry. IP RDAP resolves the hosting provider behind the exit IP.
RDAP_DOMAIN_BASE: Final[str] = "https://rdap.org/domain/"
RDAP_IP_BASE: Final[str] = "https://rdap.org/ip/"
# Certificate Transparency search — finds sibling domains sharing a cert
# (campaign mapping). JSON, no key required.
CRT_SH_BASE: Final[str] = "https://crt.sh/"
CRT_SH_MAX_RELATED: Final[int] = 25

# Domain-age risk: freshly-registered domains are a strong scam predictor. Each
# entry: (max_age_days, severity, weight). First match wins (ascending).
DOMAIN_AGE_RISK: Final[Tuple[Tuple[int, str, int], ...]] = (
    (7, "high", 20),
    (30, "high", 16),
    (90, "medium", 10),
    (180, "low", 5),
)

# --------------------------------------------------------------------------
# Phase 3 — External threat-intelligence feeds
# --------------------------------------------------------------------------
# URLhaus (abuse.ch) host lookup — free, no key. Confirms a host is a known
# malware/phishing distributor.
URLHAUS_HOST_API: Final[str] = "https://urlhaus-api.abuse.ch/v1/host/"
# Google Safe Browsing v4 — optional API key (leave blank to skip this feed).
GOOGLE_SAFE_BROWSING_KEY: Final[str] = ""
GOOGLE_SAFE_BROWSING_API: Final[str] = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)
# Being listed on a reputable feed is a near-conclusive confirmation.
THREATINTEL_HIT_WEIGHT: Final[int] = 28

# --------------------------------------------------------------------------
# Phase 3 — Visual brand-impersonation matching
# --------------------------------------------------------------------------
# Reference brand login screenshots live here as <brand>.png. The screenshot is
# dHash-compared to each; a close match is strong phishing evidence. Ships empty
# (the check simply no-ops until you add references).
VISUAL_REFERENCE_DIR: Final[str] = "brand_refs"
# Hamming-distance threshold over a 64-bit dHash; <= this counts as a match.
VISUAL_HASH_THRESHOLD: Final[int] = 12
VISUAL_MATCH_WEIGHT: Final[int] = 16

# --------------------------------------------------------------------------
# Case persistence
# --------------------------------------------------------------------------
# SQLite store of every scan, enabling historical diffing of a target over time.
CASE_DB_PATH: Final[str] = "artifacts/cases.db"

# Risk bucket cap for intelligence signals (domain age + threat-intel + visual).
RISK_INTEL_CAP: Final[int] = 45

# --------------------------------------------------------------------------
# Phase 4 — Localhost GUI
# --------------------------------------------------------------------------
# Bound to loopback ONLY. Exposing this command-center to a network would be a
# self-inflicted vulnerability — do not change the host to 0.0.0.0.
GUI_HOST: Final[str] = "127.0.0.1"
GUI_PORT: Final[int] = 8077

# --------------------------------------------------------------------------
# General networking
# --------------------------------------------------------------------------
HTTP_TIMEOUT_SECONDS: Final[float] = 20.0