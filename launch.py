from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import webbrowser

from config import GUI_HOST, GUI_PORT, TOR_SOCKS_HOST, TOR_SOCKS_PORT

ROOT = os.path.dirname(os.path.abspath(__file__))
TORRC = os.path.join(ROOT, "torrc")
BOOTSTRAP_TIMEOUT = 90


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _find_tor() -> str | None:
    found = shutil.which("tor")
    if found:
        return found
    candidates = [
        r"C:\ProgramData\chocolatey\bin\tor.exe",
        os.path.expandvars(r"%ProgramFiles%\Tor\tor.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Tor\tor.exe"),
        os.path.expandvars(r"%ProgramFiles%\Tor Browser\Browser\TorBrowser\Tor\tor.exe"),
        os.path.expanduser(r"~\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe"),
        "/usr/bin/tor", "/usr/local/bin/tor", "/opt/homebrew/bin/tor",
    ]
    for path in candidates:
        if path and os.path.exists(path):
            return path
    return None


def _port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def _install_hint() -> None:
    print("\n[!] Tor was not found on this machine.")
    print("    Install it, then re-run this launcher:")
    print("      Windows : choco install tor -y")
    print("      macOS   : brew install tor")
    print("      Debian  : sudo apt install tor")
    print("    Or run without Tor for LOCAL decoy testing only:")
    print("      python launch.py --skip-tor scan http://127.0.0.1:8090 --local\n")


def _start_tor(tor_path: str) -> subprocess.Popen | None:
    cmd = [tor_path]
    if os.path.exists(TORRC):
        cmd += ["-f", TORRC]
    else:
        print(f"[*] {TORRC} not found — starting Tor with built-in defaults.")
    print(f"[*] Starting Tor: {' '.join(cmd)}")
    proc = subprocess.Popen(
        cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )

    deadline = time.time() + BOOTSTRAP_TIMEOUT
    while time.time() < deadline:
        line = proc.stdout.readline() if proc.stdout else ""
        if not line:
            if proc.poll() is not None:
                print("[!] Tor exited before bootstrapping. Check torrc / ports.")
                return None
            continue
        line = line.strip()
        if any(tag in line for tag in ("Bootstrapped", "[warn]", "[err]", "[notice] Opening")):
            print(f"  [tor] {line}")
        if "Bootstrapped 100%" in line:
            threading.Thread(target=_drain, args=(proc,), daemon=True).start()
            return proc
    print("[!] Tor did not finish bootstrapping within the timeout.")
    return proc


def _drain(proc: subprocess.Popen) -> None:
    try:
        for line in proc.stdout:  # type: ignore[union-attr]
            if "[warn]" in line or "[err]" in line:
                print(f"  [tor] {line.strip()}")
    except OSError:
        return


def _force_kill(proc: subprocess.Popen) -> None:
    try:
        proc.kill()
    except ProcessLookupError:
        return


def _stop(proc: subprocess.Popen | None, name: str) -> None:
    if proc is None or proc.poll() is not None:
        return
    print(f"[*] Stopping {name}...")
    try:
        proc.terminate()
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        _force_kill(proc)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main() -> int:
    args = sys.argv[1:]
    skip_tor = "--skip-tor" in args
    if skip_tor:
        args.remove("--skip-tor")
    if not args:
        args = ["gui"]
    is_gui = args[0] == "gui"

    print("=" * 64)
    print("  THREAT-RECON launcher  —  plug-and-play")
    print("=" * 64)

    tor_proc: subprocess.Popen | None = None
    app: subprocess.Popen | None = None

    try:
        if skip_tor:
            print("[*] --skip-tor: not managing Tor (local/offline mode).")
        elif _port_open(TOR_SOCKS_HOST, TOR_SOCKS_PORT):
            print(f"[*] Tor already listening on {TOR_SOCKS_HOST}:{TOR_SOCKS_PORT} — reusing it.")
        else:
            tor_path = _find_tor()
            if not tor_path:
                _install_hint()
                return 1
            tor_proc = _start_tor(tor_path)
            if not _port_open(TOR_SOCKS_HOST, TOR_SOCKS_PORT):
                print("[!] SOCKS port still not reachable; remote scans may fail.")

        url = f"http://{GUI_HOST}:{GUI_PORT}"
        if is_gui:
            print(f"[*] Launching command center -> {url}")
            threading.Timer(2.0, lambda: _safe_open(url)).start()
        else:
            print(f"[*] Running: main.py {' '.join(args)}")

        app = subprocess.Popen([sys.executable, "main.py", *args], cwd=ROOT)
        app.wait()
        return app.returncode or 0

    except KeyboardInterrupt:
        print("\n[*] Interrupted — shutting down.")
        return 130
    finally:
        _stop(app, "app")
        _stop(tor_proc, "Tor")


def _safe_open(url: str) -> None:
    try:
        webbrowser.open(url)
    except webbrowser.Error:
        return


if __name__ == "__main__":
    raise SystemExit(main())
