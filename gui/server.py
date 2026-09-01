from __future__ import annotations

import asyncio
import ipaddress
import json
import secrets
import threading
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Callable

from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates

from config import (
    GUI_HOST,
    GUI_MAX_CONCURRENT_SCANS,
    GUI_MAX_QUEUE,
    GUI_PASSWORD,
    GUI_PORT,
    GUI_USERNAME,
)
from models import ScanReport, ScanStatus
from modules.logging_setup import get_logger
from modules.pipeline import run_scan
from modules.util import is_loopback, normalize_url


log = get_logger("gui.server")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
security = HTTPBasic(auto_error=False)
job_file = Path("artifacts/gui_jobs.json")

Job = dict[str, Any]
jobs: dict[str, Job] = {}
metrics = {"started": 0, "completed": 0, "failed": 0, "queue_rejected": 0}
job_queue: asyncio.Queue[str] | None = None
status_updates: asyncio.Queue[tuple[str, str, dict[str, Any] | None]] | None = None
enqueue_lock: asyncio.Lock | None = None
save_lock: asyncio.Lock | None = None


def _is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _require_auth(
    credentials: HTTPBasicCredentials | None = Depends(security),
) -> None:
    if _is_loopback_host(GUI_HOST):
        return
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Basic"},
        )

    valid_user = secrets.compare_digest(credentials.username, GUI_USERNAME)
    valid_password = secrets.compare_digest(credentials.password, GUI_PASSWORD)
    if not (valid_user and valid_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Basic"},
        )


def _load_jobs() -> None:
    try:
        content = job_file.read_text(encoding="utf-8")
    except FileNotFoundError:
        return

    loaded = json.loads(content)
    if not isinstance(loaded, dict):
        raise ValueError(f"{job_file} must contain a JSON object.")
    jobs.update(loaded)


def _write_jobs(content: str) -> None:
    job_file.parent.mkdir(parents=True, exist_ok=True)
    temporary_file = job_file.with_suffix(".tmp")
    temporary_file.write_text(content, encoding="utf-8")
    temporary_file.replace(job_file)


async def _save_jobs() -> None:
    if save_lock is None:
        raise RuntimeError("Job persistence is not running.")
    content = json.dumps(jobs, indent=2, sort_keys=True)
    async with save_lock:
        await asyncio.to_thread(_write_jobs, content)


def _job_queue() -> asyncio.Queue[str]:
    if job_queue is None:
        raise RuntimeError("Scan queue is not running.")
    return job_queue


def _status_queue() -> asyncio.Queue[tuple[str, str, dict[str, Any] | None]]:
    if status_updates is None:
        raise RuntimeError("Status writer is not running.")
    return status_updates


def _enqueue_lock() -> asyncio.Lock:
    if enqueue_lock is None:
        raise RuntimeError("Scan queue is not running.")
    return enqueue_lock


def _status_hook(job_id: str) -> Callable[[str], None]:
    loop = asyncio.get_running_loop()
    queue = _status_queue()
    owner_thread = threading.get_ident()

    def update(scan_status: str) -> None:
        update_item = (job_id, scan_status, None)
        if threading.get_ident() == owner_thread:
            queue.put_nowait(update_item)
        else:
            loop.call_soon_threadsafe(queue.put_nowait, update_item)

    return update


async def _run_job(job_id: str) -> None:
    job = jobs[job_id]
    try:
        report: ScanReport = await run_scan(
            job["target"],
            status_hook=_status_hook(job_id),
            direct=job["direct"],
        )
    except (OSError, ValueError) as error:
        log.error("Scan %s failed: %s", job_id, error)
        await _status_queue().put(
            (job_id, ScanStatus.FAILED, {"errors": [str(error)]})
        )
        return

    await _status_queue().put((job_id, report.status, report.as_dict()))


async def _scan_worker() -> None:
    queue = _job_queue()
    while True:
        job_id = await queue.get()
        metrics["started"] += 1
        try:
            await _run_job(job_id)
        finally:
            queue.task_done()


async def _write_status_updates() -> None:
    queue = _status_queue()
    while True:
        job_id, scan_status, report = await queue.get()
        try:
            job = jobs[job_id]
            job["status"] = scan_status
            if report is not None:
                job["report"] = report
                if scan_status == ScanStatus.DONE:
                    metrics["completed"] += 1
                elif scan_status == ScanStatus.FAILED:
                    metrics["failed"] += 1
            await _save_jobs()
        finally:
            queue.task_done()


@asynccontextmanager
async def _lifespan(_: FastAPI) -> AsyncIterator[None]:
    global enqueue_lock, job_queue, save_lock, status_updates

    if GUI_MAX_CONCURRENT_SCANS < 1:
        raise ValueError("SCAMWATCH_GUI_MAX_CONCURRENT_SCANS must be at least 1.")
    if GUI_MAX_QUEUE < 1:
        raise ValueError("SCAMWATCH_GUI_MAX_QUEUE must be at least 1.")
    if not _is_loopback_host(GUI_HOST) and not (GUI_USERNAME and GUI_PASSWORD):
        raise RuntimeError(
            "SCAMWATCH_GUI_USERNAME and SCAMWATCH_GUI_PASSWORD are required "
            "when binding the GUI outside loopback."
        )

    _load_jobs()
    job_queue = asyncio.Queue(maxsize=GUI_MAX_QUEUE)
    status_updates = asyncio.Queue()
    enqueue_lock = asyncio.Lock()
    save_lock = asyncio.Lock()
    status_task = asyncio.create_task(_write_status_updates())
    workers = [
        asyncio.create_task(_scan_worker())
        for _ in range(GUI_MAX_CONCURRENT_SCANS)
    ]

    for job_id, job in jobs.items():
        if job["status"] == ScanStatus.QUEUED:
            await job_queue.put(job_id)
        elif job["status"] not in (ScanStatus.DONE, ScanStatus.FAILED):
            job["status"] = ScanStatus.FAILED
            job["report"] = {"errors": ["Scan interrupted by server restart."]}
    await _save_jobs()

    try:
        yield
    finally:
        status_task.cancel()
        for worker in workers:
            worker.cancel()
        await asyncio.gather(status_task, *workers, return_exceptions=True)
        job_queue = None
        status_updates = None
        enqueue_lock = None
        save_lock = None


app = FastAPI(
    title="THREAT-RECON Command Center",
    docs_url=None,
    redoc_url=None,
    dependencies=[Depends(_require_auth)],
    lifespan=_lifespan,
)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "index.html")


@app.post("/scan")
async def start_scan(url: str = Form(...)) -> JSONResponse:
    target = normalize_url(url)
    if not target:
        raise HTTPException(status_code=400, detail="A target URL is required.")

    queue = _job_queue()
    async with _enqueue_lock():
        if queue.full():
            metrics["queue_rejected"] += 1
            raise HTTPException(status_code=429, detail="Scan queue is full.")

        job_id = uuid.uuid4().hex
        direct = is_loopback(target)
        jobs[job_id] = {
            "target": target,
            "direct": direct,
            "status": ScanStatus.QUEUED,
            "report": None,
        }
        await _save_jobs()
        queue.put_nowait(job_id)
    log.info("Queued scan %s for %s (direct=%s)", job_id, target, direct)
    return JSONResponse({"scan_id": job_id, "target": target, "direct": direct})


@app.get("/status/{scan_id}")
async def scan_status(scan_id: str) -> JSONResponse:
    job = jobs.get(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown scan id.")

    scan_state = job["status"]
    done = scan_state in (ScanStatus.DONE, ScanStatus.FAILED)
    return JSONResponse(
        {
            "scan_id": scan_id,
            "status": scan_state,
            "done": done,
            "report": job["report"] if done else None,
        }
    )


@app.get("/metrics")
async def prometheus_metrics() -> PlainTextResponse:
    queue = _job_queue()
    lines = [
        "# TYPE scamwatch_scans_started_total counter",
        f"scamwatch_scans_started_total {metrics['started']}",
        "# TYPE scamwatch_scans_completed_total counter",
        f"scamwatch_scans_completed_total {metrics['completed']}",
        "# TYPE scamwatch_scans_failed_total counter",
        f"scamwatch_scans_failed_total {metrics['failed']}",
        "# TYPE scamwatch_scan_queue_rejected_total counter",
        f"scamwatch_scan_queue_rejected_total {metrics['queue_rejected']}",
        "# TYPE scamwatch_scan_queue_depth gauge",
        f"scamwatch_scan_queue_depth {queue.qsize()}",
    ]
    return PlainTextResponse("\n".join(lines) + "\n")


def serve() -> None:
    log.info("Starting command center on http://%s:%s", GUI_HOST, GUI_PORT)
    import uvicorn

    uvicorn.run(app, host=GUI_HOST, port=GUI_PORT, log_level="info")
