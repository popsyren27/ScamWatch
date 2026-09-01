from __future__ import annotations

import asyncio
import uuid
from pathlib import Path
from typing import Any, Callable

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from config import GUI_HOST, GUI_PORT
from models import ScanReport, ScanStatus
from modules.logging_setup import get_logger
from modules.pipeline import run_scan
from modules.util import is_loopback, normalize_url


log = get_logger("gui.server")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
app = FastAPI(title="THREAT-RECON Command Center", docs_url=None, redoc_url=None)

Job = dict[str, Any]
jobs: dict[str, Job] = {}


def _status_hook(job_id: str) -> Callable[[str], None]:
    def update(status: str) -> None:
        jobs[job_id]["status"] = status

    return update


async def _run_job(job_id: str, target: str, direct: bool) -> None:
    try:
        report: ScanReport = await run_scan(
            target,
            status_hook=_status_hook(job_id),
            direct=direct,
        )
    except (OSError, ValueError) as error:
        log.error("Scan %s failed: %s", job_id, error)
        jobs[job_id]["status"] = ScanStatus.FAILED
        jobs[job_id]["report"] = {"errors": [str(error)]}
        return

    jobs[job_id]["status"] = report.status
    jobs[job_id]["report"] = report.as_dict()


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "index.html")


@app.post("/scan")
async def start_scan(url: str = Form(...)) -> JSONResponse:
    target = normalize_url(url)
    if not target:
        raise HTTPException(status_code=400, detail="A target URL is required.")

    job_id = uuid.uuid4().hex
    direct = is_loopback(target)
    jobs[job_id] = {"status": ScanStatus.QUEUED, "report": None}
    asyncio.create_task(_run_job(job_id, target, direct))
    log.info("Queued scan %s for %s (direct=%s)", job_id, target, direct)
    return JSONResponse({"scan_id": job_id, "target": target, "direct": direct})


@app.get("/status/{scan_id}")
async def scan_status(scan_id: str) -> JSONResponse:
    job = jobs.get(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown scan id.")

    status = job["status"]
    done = status in (ScanStatus.DONE, ScanStatus.FAILED)
    return JSONResponse(
        {
            "scan_id": scan_id,
            "status": status,
            "done": done,
            "report": job["report"] if done else None,
        }
    )


def serve() -> None:
    log.info("Starting command center on http://%s:%s", GUI_HOST, GUI_PORT)
    import uvicorn

    uvicorn.run(app, host=GUI_HOST, port=GUI_PORT, log_level="info")
