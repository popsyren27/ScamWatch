"""
main.py — Dispatcher / CLI entrypoint.

Short notes to self:
- Parses CLI and calls the real work in `modules/`.
- Keep this thin. If you find logic creeping in here, move it back to modules.

TODO:
- Add better CLI validation for weird URLs.

Problems I've seen:
- Catch-all exception handling hides root causes; check module logs when
    something fails instead of expecting tracebacks here.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from urllib.parse import urlparse

from modules.logging_setup import get_logger

log = get_logger("main")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threat-recon",
        description="Passive scam-site reconnaissance & evidence generator.",
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    sub.add_parser("gui", help="Launch the localhost command center (FastAPI).")

    scan = sub.add_parser("scan", help="Run a single headless scan.")
    scan.add_argument("url", help="Target URL (http/https; bare host => https).")
    scan.add_argument("--json", action="store_true",
                      help="Print the full report JSON to stdout.")
    scan.add_argument("--local", action="store_true",
                      help="Direct (no-Tor) mode for LOOPBACK targets only — e.g. "
                           "testing the bundled decoy on 127.0.0.1. Refused for any "
                           "remote host so anonymity is never silently disabled.")

    hist = sub.add_parser("history", help="Show prior scans of a target from the case DB.")
    hist.add_argument("url", help="Target URL to show history for.")
    return parser


def _validate_target(raw: str) -> str:
    """Validate a CLI-supplied target and return its normalized form."""
    candidate = raw.strip()
    if not candidate:
        raise ValueError("Target URL cannot be empty.")
    if "://" not in candidate:
        candidate = f"https://{candidate}"

    parsed = urlparse(candidate)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme {parsed.scheme!r} (only http/https)")
    if not parsed.netloc:
        raise ValueError(f"not a valid URL: {raw!r}")
    return candidate


def _validated_or_none(raw_url: str) -> str | None:
    """Validate a URL argument, printing an error and returning None if invalid."""
    try:
        return _validate_target(raw_url)
    except ValueError as exc:
        print(f"Invalid target: {exc}", file=sys.stderr)
        return None


async def _dispatch_scan(url: str, as_json: bool, direct: bool) -> int:
    """Dispatch a one-off CLI scan into the pipeline module."""
    # imported here so `gui` mode need not import the whole scan stack
    from modules.pipeline import run_scan

    def hook(status: str) -> None:
        # print to stderr so JSON output (stdout) stays clean when requested
        print(f"  [*] {status}", file=sys.stderr)

    report = await run_scan(url, status_hook=hook, direct=direct)
    if as_json:
        print(json.dumps(report.as_dict(), indent=2, ensure_ascii=False))
    else:
        _print_summary(report)

    # non-"Complete" states (e.g. the anonymity gate failing) exit non-zero
    # so CI / wrapper scripts can detect the failure automatically
    return 0 if report.status == "Complete" else 1


def _print_summary(report) -> None:
    """Terse human summary for the terminal."""
    print(f"\n=== THREAT-RECON :: {report.target_url} ===")
    print(f"Status     : {report.status}")
    if report.risk is not None:
        print(f"RISK       : {report.risk.level.upper()} ({report.risk.score}/100)")
        print(f"Verdict    : {report.risk.summary}")
    if report.proxy:
        print(f"Exit IP    : {report.proxy.exit_ip} "
              f"(anonymous={report.proxy.is_anonymous})")
    print(f"Heuristics : {len(report.heuristics)} signal(s)")
    print(f"Tech stack : {len(report.tech_stack)} component(s)")
    print(f"CVEs       : {len(report.cves)}")
    exposed = sum(1 for m in report.misconfigs if m.exposed)
    print(f"Exposed    : {exposed} path(s)")
    print(f"Security   : {len(report.security_findings)} posture finding(s)")
    if report.intel:
        age = report.intel.age_days
        print(f"Domain     : {report.intel.domain or '—'}"
              f"{f' ({age}d old)' if age is not None else ''}"
              f"{f' · registrar {report.intel.registrar}' if report.intel.registrar else ''}")
        if report.intel.related_domains:
            print(f"Campaign   : {len(report.intel.related_domains)} sibling domain(s)")
    listed = [t.source for t in report.threat_intel if t.listed]
    if listed:
        print(f"ThreatFeed : LISTED on {', '.join(listed)}")
    if report.visual_matches:
        print(f"Visual     : impersonates {', '.join(v.brand for v in report.visual_matches)}")
    if report.diff_summary:
        print("Change     : " + report.diff_summary[0])
    if report.errors:
        print(f"Notes      : {len(report.errors)} operational note(s)")

    # reports are only written once the pipeline reaches Phase 5; the anonymity
    # gate aborts earlier, so don't claim artifacts that were never produced
    if report.status == "Complete":
        print("Reports written to ./artifacts/")
    else:
        for note in report.errors:
            print(f"  - {note}")
    print()


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    args = _build_parser().parse_args(argv)
    try:
        if args.mode == "gui":
            from gui.server import serve
            serve()
            return 0

        if args.mode == "scan":
            url = _validated_or_none(args.url)
            if url is None:
                return 2
            return asyncio.run(_dispatch_scan(url, args.json, args.local))

        if args.mode == "history":
            url = _validated_or_none(args.url)
            if url is None:
                return 2
            from modules.store import history
            rows = history(url)
            if not rows:
                print("No prior scans recorded for that target.")
                return 0
            print(f"\nScan history for {url} ({len(rows)} record(s)):")
            for r in rows:
                print(f"  {r['timestamp']}  {r['risk_level']:8s} {r['risk_score']:3d}/100")
            print()
            return 0
    except KeyboardInterrupt:
        log.info("Interrupted by operator.")
        return 130
    except Exception as exc:
        # top-level safety net: detailed traces are in module logs, keep CLI tidy
        log.critical("Fatal dispatcher error: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())