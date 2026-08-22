"""
logging_setup.py — Single shared logger (quick notes).

Keeps a consistent format so I don't have to think about logger setup everywhere.
It intentionally swallows errors during setup — logging should not crash a scan.

TODO:
- Add file rotation later if disk fills up during long tests.
"""

from __future__ import annotations

import logging
from typing import Final

_LOG_FORMAT: Final[str] = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_configured: bool = False


def get_logger(name: str) -> logging.Logger:
    """Return a module logger, configuring root handlers exactly once."""
    global _configured
    try:
        if not _configured:
            logging.basicConfig(level=logging.INFO, format=_LOG_FORMAT)
            _configured = True
    except Exception:
        # if the host environment forbids stream handlers, degrade to a bare
        # logger rather than aborting the scan
        pass
    return logging.getLogger(name)