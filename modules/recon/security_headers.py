"""
security_headers.py — Passive security audit (my notes).

Read-only checks on headers, cookies and DOM for issues like missing HSTS/CSP,
mixed content, insecure forms or leaked secrets. No active probing.

TODO:
- Add more regexes for modern token formats if I see new leaks.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Final, List, Optional, Pattern, Tuple
from urllib.parse import urlparse

from models import IngestedPage, SecurityFinding
from modules.logging_setup import get_logger
from modules.recon import knowledge_loader as kb

log = get_logger("recon.security")

_VERSIONED_HEADERS: Final[Tuple[str, ...]] = (
    "server", "x-powered-by", "x-aspnet-version", "x-generator",
)

# Session-cookie name hints — these are the cookies whose missing flags matter.
_SESSION_COOKIE_HINTS: Final[Tuple[str, ...]] = (
    "session", "sess", "sid", "auth", "token", "jwt", "login", "phpsessid",
    "jsessionid", "asp.net_sessionid", "laravel_session", "connect.sid",
)

# Max number of duplicate matches we'll report per secret pattern — no flooding.
_MAX_MATCHES_PER_PATTERN: int = 3

# Max mixed-content assets to report — one screenshot's worth is plenty.
_MAX_MIXED_CONTENT_EVIDENCE: int = 5

# Anti-CSRF field-name hints we look for in a form before flagging it as missing one.
_CSRF_FIELD_HINTS: Tuple[str, ...] = ("csrf", "token", "nonce", "authenticity")

# (label, severity, compiled-pattern, redact?) for leaked-secret detection.
# Patterns are specific prefixes/shapes to keep false positives low.
_SECRET_PATTERNS: Final[Tuple[Tuple[str, str, Pattern[str], bool], ...]] = (
    ("AWS access key id", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), True),
    ("Google API key", "high", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), True),
    ("Stripe live secret key", "high", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{16,}\b"), True),
    ("GitHub token", "high", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), True),
    ("Slack token", "high", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"), True),
    ("Private key block", "high",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), False),
    ("Google service-account private key", "high",
     re.compile(r"\"private_key\"\s*:\s*\"-----BEGIN"), False),
    ("JWT (JSON Web Token)", "medium",
     re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"), True),
    ("HTTP basic-auth credentials in URL", "high",
     re.compile(r"https?://[^/\s:@\"']+:[^/\s:@\"']+@", re.I), True),
    ("Hard-coded secret assignment", "medium",
     re.compile(r"(?i)(?:api[_-]?key|secret|client[_-]?secret|access[_-]?token|"
                r"auth[_-]?token|password|passwd)\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']"), True),
    ("Internal/RFC-1918 IP address", "low",
     re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
                r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"), False),
)


def _redact(value: str) -> str:
    """Show just enough of a secret to prove it's real. Never the whole thing."""
    v = value.strip()
    if len(v) <= 12:
        return v[:4] + "…"
    return f"{v[:8]}…{v[-4:]} (len {len(v)})"


def _lower_headers(page: IngestedPage) -> Dict[str, str]:
    """Flatten response headers to lowercase keys so lookups don't fight casing."""
    return {str(k).lower(): str(v) for k, v in (page.response_headers or {}).items()}


def _transport(page: IngestedPage) -> List[SecurityFinding]:
    """Flag plain HTTP."""
    if urlparse(page.final_url or "").scheme.lower() != "http":
        return []
    return [SecurityFinding(
        category="no_tls",
        detail="Served over plaintext HTTP — credentials and payment data travel "
               "unencrypted and are trivially interceptable.",
        severity="medium", evidence=(page.final_url or "")[:160])]


def _missing_headers(h: Dict[str, str]) -> List[SecurityFinding]:
    """Check every expected security header is actually present."""
    out: List[SecurityFinding] = []
    for _rule_id, name, severity, detail in kb.load_security_headers_expected():
        if not h.get(name, "").strip():
            out.append(SecurityFinding(category="missing_header", detail=detail,
                                        severity=severity, evidence=name))
    return out


def _csp_weakness(h: Dict[str, str]) -> List[SecurityFinding]:
    """Flag a present-but-weak Content-Security-Policy."""
    out: List[SecurityFinding] = []
    csp = h.get("content-security-policy", "").lower()
    if not csp:
        return out  # absence is already reported by _missing_headers
    if "unsafe-inline" in csp:
        out.append(SecurityFinding(category="csp_weak",
            detail="CSP allows 'unsafe-inline' — inline scripts/styles are permitted, "
                   "defeating much of CSP's XSS protection.", severity="low", evidence="unsafe-inline"))
    if "unsafe-eval" in csp:
        out.append(SecurityFinding(category="csp_weak",
            detail="CSP allows 'unsafe-eval' — eval()/Function() remain usable by "
                   "injected code.", severity="low", evidence="unsafe-eval"))
    if re.search(r"(?:default|script)-src[^;]*\*", csp):
        out.append(SecurityFinding(category="csp_weak",
            detail="CSP uses a wildcard '*' source for scripts — any origin may load "
                   "executable code.", severity="medium", evidence="* source"))
    return out


def _cors(h: Dict[str, str]) -> List[SecurityFinding]:
    """Flag wide-open CORS, worse if it's paired with credentials."""
    acao = h.get("access-control-allow-origin", "").strip()
    acac = h.get("access-control-allow-credentials", "").strip().lower()
    if acao != "*":
        return []
    if acac == "true":
        return [SecurityFinding(category="cors",
            detail="CORS allows ANY origin (*) WITH credentials — any site can read "
                   "authenticated responses on the victim's behalf.",
            severity="high", evidence="ACAO:* + ACAC:true")]
    return [SecurityFinding(category="cors",
        detail="CORS allows any origin (Access-Control-Allow-Origin: *) — "
               "review whether sensitive data is exposed cross-origin.",
        severity="low", evidence="ACAO:*")]


def _version_disclosure(h: Dict[str, str]) -> List[SecurityFinding]:
    """Flag headers that leak exact software versions (easy CVE targeting)."""
    out: List[SecurityFinding] = []
    for hdr in _VERSIONED_HEADERS:
        val = h.get(hdr, "")
        if val and any(ch.isdigit() for ch in val):
            out.append(SecurityFinding(category="info_disclosure",
                detail=f"Software version disclosed via the '{hdr}' header — eases "
                       "targeted exploitation of known CVEs.",
                severity="low", evidence=f"{hdr}: {val}"[:160]))
    return out


def _cookie_flags(h: Dict[str, str]) -> List[SecurityFinding]:
    """Inspect Set-Cookie for missing protective attributes on session cookies."""
    out: List[SecurityFinding] = []
    raw = h.get("set-cookie", "")
    if not raw:
        return out
    low = raw.lower()
    name = raw.split("=", 1)[0].strip()[:40] or "cookie"
    looks_session = any(hint in low for hint in _SESSION_COOKIE_HINTS)
    # session cookies warrant the strongest flags; rate non-session ones lower
    base = "medium" if looks_session else "low"
    if "httponly" not in low:
        out.append(SecurityFinding(category="weak_cookie",
            detail="Cookie set without HttpOnly — readable by injected JavaScript "
                   "(session theft via XSS).", severity=base, evidence=name))
    if "secure" not in low:
        out.append(SecurityFinding(category="weak_cookie",
            detail="Cookie set without the Secure flag — may be sent over plaintext HTTP.",
            severity=base, evidence=name))
    if "samesite" not in low:
        out.append(SecurityFinding(category="weak_cookie",
            detail="Cookie set without SameSite — exposed to cross-site request forgery.",
            severity="info", evidence=name))
    return out


def _http_assets_from_dom(dom: str) -> set:
    """Regex-scrape src/href/action attributes pointing at plain HTTP."""
    return set(re.findall(r"(?:src|href|action)\s*=\s*[\"'](http://[^\"']+)", dom, re.I))


def _http_assets_from_requests(requests: List[str]) -> set:
    """Same idea but from the recorded 'METHOD url' network log lines."""
    urls: set = set()
    for req in requests:
        url = req.split(" ", 1)[-1]
        if url.lower().startswith("http://"):
            urls.add(url)
    return urls


def _mixed_content(page: IngestedPage) -> List[SecurityFinding]:
    """An HTTPS page that loads sub-resources over HTTP (downgrade/inject risk)."""
    if urlparse(page.final_url or "").scheme.lower() != "https":
        return []
    dom = page.dom_html or ""
    http_assets = _http_assets_from_dom(dom) | _http_assets_from_requests(page.network_requests or [])
    return [
        SecurityFinding(category="mixed_content",
            detail="HTTPS page loads a sub-resource over plaintext HTTP — content can be "
                   "tampered with in transit.", severity="low", evidence=asset[:160])
        for asset in list(http_assets)[:_MAX_MIXED_CONTENT_EVIDENCE]
    ]


def _form_has_password_field(form: Any) -> bool:
    """Is this actually a login/credential form, or just a newsletter box?"""
    return any((i.get("type") or "").lower() == "password" for i in form.find_all("input"))


def _form_action_finding(form: Any, page_host: str) -> Optional[SecurityFinding]:
    """Check where the form actually submits to — plaintext or a different host."""
    action = (form.get("action") or "").strip()
    if action.lower().startswith("http://"):
        return SecurityFinding(category="insecure_form",
            detail="Login/credential form submits over plaintext HTTP — entered "
                   "passwords are sent unencrypted.", severity="high",
            evidence=action[:160])
    if action.startswith("http"):
        action_host = urlparse(action).hostname or ""
        if action_host and page_host and action_host != page_host:
            return SecurityFinding(category="insecure_form",
                detail="Credential form posts to a DIFFERENT host than the page "
                       "— classic phishing/exfil pattern.", severity="medium",
                evidence=f"{page_host} -> {action_host}"[:160])
    return None


def _form_csrf_finding(form: Any) -> Optional[SecurityFinding]:
    """Look for anything that smells like an anti-CSRF token field."""
    names = " ".join((i.get("name") or "") for i in form.find_all("input")).lower()
    if any(hint in names for hint in _CSRF_FIELD_HINTS):
        return None
    return SecurityFinding(category="insecure_form",
        detail="Credential form has no apparent anti-CSRF token field.",
        severity="low", evidence="no csrf token")


def _audit_one_form(form: Any, page_host: str) -> List[SecurityFinding]:
    """Run all the credential-form checks on a single <form> tag."""
    if not _form_has_password_field(form):
        return []
    out: List[SecurityFinding] = []
    action_finding = _form_action_finding(form, page_host)
    if action_finding:
        out.append(action_finding)
    csrf_finding = _form_csrf_finding(form)
    if csrf_finding:
        out.append(csrf_finding)
    return out


def _insecure_forms(page: IngestedPage) -> List[SecurityFinding]:
    """Password forms posted insecurely or without anti-CSRF protection."""
    dom = page.dom_html or ""
    if not dom:
        return []
    page_host = urlparse(page.final_url or "").hostname or ""
    try:
        from bs4 import BeautifulSoup  # type: ignore

        soup = BeautifulSoup(dom, "html.parser")
        findings: List[SecurityFinding] = []
        for form in soup.find_all("form"):
            findings.extend(_audit_one_form(form, page_host))
        return findings
    except Exception as exc:
        log.warning("Form audit degraded (bs4 issue): %s", exc)
        return []


def _matches_for_pattern(haystack: str, label: str, severity: str,
                          pattern: Pattern[str], redact: bool) -> List[SecurityFinding]:
    """Find (capped, de-duped) hits for one secret pattern in the page content."""
    out: List[SecurityFinding] = []
    seen: set = set()
    for match in pattern.findall(haystack):
        if isinstance(match, str):
            token = match
        elif match:
            token = match[0]
        else:
            token = ""
        token = str(token)

        if not token or token in seen:
            continue
        seen.add(token)
        out.append(SecurityFinding(category="sensitive_exposure",
            detail=f"Possible {label} exposed in page content/assets.",
            severity=severity,
            evidence=_redact(token) if redact else label))
        if len(seen) >= _MAX_MATCHES_PER_PATTERN:
            break
    return out


def _sensitive_exposure(page: IngestedPage) -> List[SecurityFinding]:
    """Scan the captured DOM (and request URLs) for leaked secrets."""
    haystack = (page.dom_html or "") + "\n" + "\n".join(page.network_requests or [])
    if not haystack.strip():
        return []
    out: List[SecurityFinding] = []
    for label, severity, pattern, redact in _SECRET_PATTERNS:
        out.extend(_matches_for_pattern(haystack, label, severity, pattern, redact))
    return out


def audit_security(page: IngestedPage) -> List[SecurityFinding]:
    """Run the full passive security/exposure audit. Never raises."""
    findings: List[SecurityFinding] = []
    try:
        h = _lower_headers(page)
        findings.extend(_transport(page))
        findings.extend(_missing_headers(h))
        findings.extend(_csp_weakness(h))
        findings.extend(_cors(h))
        findings.extend(_version_disclosure(h))
        findings.extend(_cookie_flags(h))
        findings.extend(_mixed_content(page))
        findings.extend(_insecure_forms(page))
        findings.extend(_sensitive_exposure(page))
    except Exception as exc:
        # something in the audit chain broke — keep whatever we already found
        log.error("Security audit error (continuing): %s", exc)
    finally:
        log.info("Security audit complete: %d finding(s).", len(findings))
    return findings