"""
evidence.py — Write SHA-256 manifest for artifacts (quick notes).

Produce a simple MANIFEST.sha256.json listing each artifact's hash so I can
prove files weren't altered after capture.

TODO:
- Maybe add an optional GPG signing step if I need stronger chain-of-custody.
- Emit machine-readable error codes for the UI.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Dict, Optional

from modules.logging_setup import get_logger

log = get_logger("evidence")


def sha256_file(path: str) -> Optional[str]:
    """Streaming SHA-256 of a file, or None if it cannot be read."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as exc:
        # can't read/hash the file — warn and continue, useful for flaky FS mounts
        log.warning("Could not hash %s: %s", path, exc)
        return None


def hash_files(paths) -> Dict[str, str]:
    """Map {basename: sha256} for every existing path provided."""
    out: Dict[str, str] = {}
    for p in paths:
        if p and os.path.exists(p):
            digest = sha256_file(p)
            if digest:
                out[os.path.basename(p)] = digest
    return out


def write_manifest(out_dir: str, target_url: str, timestamp_utc: str,
                   hashes: Dict[str, str]) -> Optional[str]:
    """Write a SHA-256 manifest alongside the artifacts; return its path."""
    try:
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, "MANIFEST.sha256.json")
        manifest = {
            "tool": "THREAT-RECON",
            "target_url": target_url,
            "captured_utc": timestamp_utc,
            "algorithm": "SHA-256",
            "files": [{"name": name, "sha256": digest}
                      for name, digest in sorted(hashes.items())],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)
        log.info("Evidence manifest written: %s (%d file(s)).", path, len(hashes))
        return path
    except Exception as exc:
        # TODO: surface this to the operator UI instead of just logging
        log.error("Failed to write evidence manifest: %s", exc)
        return None