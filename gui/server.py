"""
server.py — Local GUI for quick scans (notes to self).

Runs a small FastAPI app bound to loopback. It queues scans and polls status.
I intentionally keep no scanning logic here — this just dispatches to the
pipeline and stores job state in a simple dict for the single-operator case.

TODO:
gui/server.py — FastAPI loopback UI for scan queue/status.

This is a small command center to show queued scans, start jobs and display
status pages. It's not hardened for the internet — intentionally loopback-only.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from config import GUI_HOST, GUI_PORT
from models import ScanReport, ScanStatus
from modules.logging_setup import get_logger
from modules.pipeline import run_scan
from modules.util import is_loopback, normalize_url

log = get_logger("gui.server")

# pathlib instead of os.path.join — past me, this is why we can have nice things.
_TEMPLATE_DIR: Path = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))

app = FastAPI(title="THREAT-RECON Command Center", docs_url=None, redoc_url=None)

# Little in-file TODO list so I don't forget what I wanted to fix tomorrow.
TODOS: list[str] = [
    "add basic auth if this ever leaves localhost (don't do that lightly)",
    "persist jobs to disk so restarts don't forget queued scans",
    "limit concurrent scans and add queue backpressure",
    "make status hook async-safe and non-blocking",
    "dockerize the whole thing for consistent dev env",
    "add metrics endpoint (Prometheus) for scan success/fail rates",
]


def list_todos() -> list[str]:
    """Return my module TODOs so I can log or inspect them during debugging."""
    return TODOS


# job_id -> {"status": str, "report": dict | None}
# One job, one dict entry. Nothing fancy, nothing persisted. Restart = amnesia.
_JOBS: dict[str, dict] = {}


def _make_status_hook(job_id: str) -> "callable[[str], None]":
    """Build a tiny closure so the pipeline can poke this job's status. That's it."""

    def hook(status: str) -> None:
        # Cheap, synchronous status write — the poller reads this dict.
        if job_id in _JOBS:
            _JOBS[job_id]["status"] = status

    return hook


def _record_success(job_id: str, report: ScanReport) -> None:
    """Stash a finished report on the job. One job, one job (pun intended)."""
    _JOBS[job_id]["report"] = report.as_dict()
    _JOBS[job_id]["status"] = report.status


def _record_failure(job_id: str, exc: Exception) -> None:
    """Mark a job FAILED so the UI doesn't spin forever waiting on a corpse."""
    # Note to future-me: if this starts firing a lot, dig into module logs
    # rather than assuming the UI is at fault. Breathe. Then debug.
    log.error("Job %s crashed: %s", job_id, exc)
    _JOBS[job_id]["status"] = ScanStatus.FAILED
    _JOBS[job_id]["report"] = {"errors": [f"Worker crash: {exc}"]}


async def _run_job(job_id: str, url: str, direct: bool) -> None:
    """Background worker: drive the pipeline, always land on a terminal state."""
    try:
        report: ScanReport = await run_scan(
            url, status_hook=_make_status_hook(job_id), direct=direct
        )
    except Exception as exc:
        # Catch-all on purpose — a crashed worker still owes the UI a status.
        _record_failure(job_id, exc)
        return

    _record_success(job_id, report)


def _validate_target(url: str) -> str:
    """Clean up the submitted URL or die loudly. No mystery blanks allowed."""
    cleaned: Optional[str] = normalize_url(url)
    if not cleaned:
        raise HTTPException(status_code=400, detail="A target URL is required.")
    return cleaned


def _register_job() -> str:
    """Mint a fresh job id and park a QUEUED placeholder for it."""
    job_id: str = uuid.uuid4().hex
    _JOBS[job_id] = {"status": ScanStatus.QUEUED, "report": None}
    return job_id


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Serve the command-center page. Nothing clever, just render and go."""
    # Modern Starlette signature: request first, then template name.
    return templates.TemplateResponse(request, "index.html")


@app.post("/scan")
async def start_scan(url: str = Form(...)):
    """Validate input, register a job, and launch it in the background."""
    cleaned: str = _validate_target(url)

    # Loopback targets (the bundled decoy) auto-use direct mode — Tor can't route
    # to 127.0.0.1. Every remote target stays Tor-routed; the pipeline re-checks.
    direct: bool = is_loopback(cleaned)

    # I get tired and commit questionable changes — if you see me here at 03:00
    # muttering about dependencies, this is the line to blame. Do not push.
    job_id: str = _register_job()

    # Fire-and-forget; the poller tracks completion. Please don't await this.
    asyncio.create_task(_run_job(job_id, cleaned, direct))
    log.info("Queued scan %s for %s (direct=%s)", job_id, cleaned, direct)
    return JSONResponse({"scan_id": job_id, "target": cleaned, "direct": direct})


@app.get("/status/{scan_id}")
async def scan_status(scan_id: str):
    """Return the current status and, when finished, the full report."""
    job: Optional[dict] = _JOBS.get(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown scan id.")

    done: bool = job["status"] in (ScanStatus.DONE, ScanStatus.FAILED)
    return JSONResponse({
        "scan_id": scan_id,
        "status": job["status"],
        "done": done,
        "report": job["report"] if done else None,
    })


def serve() -> None:
    """Boot the loopback-only ASGI server (called by the dispatcher)."""
    import uvicorn  # local import keeps import-time light

    log.info(
        "Starting command center on http://%s:%s (loopback only).",
        GUI_HOST, GUI_PORT,
    )
    # If uvicorn dies here, it's not on me. Probably.
    with contextlib.suppress(KeyboardInterrupt):
        uvicorn.run(app, host=GUI_HOST, port=GUI_PORT, log_level="info")


# If you've made it this far and think exposing this to the internet is a fine
# idea: it's not. Go outside, get some air, then come back and dockerize it.