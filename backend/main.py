"""FastAPI app. Thin layer over backend.pipeline — no business logic lives
here beyond upload handling and an in-memory run registry for the
confirm/reject demo flow.

Run: uvicorn backend.main:app --reload --port 8000
"""
from __future__ import annotations

import json
import shutil
import tempfile
import uuid
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import pipeline
from .models import PipelineResult
from .tools import ToolLedger

app = FastAPI(title="Doorman API", version="1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = Path(tempfile.gettempdir()) / "doorman_uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

RUNS: dict[str, dict] = {}  # run_id -> {"result": PipelineResult, "ledger": ToolLedger}

DEFAULT_KEYWORDS = ["python", "sql", "docker", "kubernetes", "aws"]
REPORT_PATH = Path(__file__).parent.parent / "eval" / "report.json"


@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.post("/api/analyze")
async def analyze(
    file: UploadFile = File(...),
    mode: str = Form("guarded"),
    candidate_email: str = Form("candidate@example.com"),
):
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(400, "Only PDF files are supported")

    run_id = str(uuid.uuid4())
    dest = UPLOAD_DIR / f"{run_id}.pdf"
    with open(dest, "wb") as f:
        shutil.copyfileobj(file.file, f)

    run_fn = pipeline.run_naive if mode == "naive" else pipeline.run_guarded
    try:
        result = run_fn(str(dest), DEFAULT_KEYWORDS, candidate_email=candidate_email)
    finally:
        dest.unlink(missing_ok=True)

    RUNS[run_id] = {"result": result, "ledger": ToolLedger()}
    return JSONResponse({"run_id": run_id, **result.model_dump(mode="json")})


@app.post("/api/runs/{run_id}/confirm")
async def confirm(run_id: str, index: int = Form(...)):
    run = RUNS.get(run_id)
    if not run:
        raise HTTPException(404, "unknown run_id")
    result: PipelineResult = run["result"]
    if index < 0 or index >= len(result.pending_actions):
        raise HTTPException(400, "invalid pending-action index")

    call = result.pending_actions.pop(index)
    ledger: ToolLedger = run["ledger"]
    if call.tool_name == "send_email":
        ledger.send_email(**call.arguments)
    elif call.tool_name == "write_ats":
        ledger.write_ats(candidate_id=result.filename, status=call.arguments.get("status", "unknown"))

    return {"executed": call.model_dump(), "remaining_pending": len(result.pending_actions)}


@app.post("/api/runs/{run_id}/reject")
async def reject(run_id: str, index: int = Form(...)):
    run = RUNS.get(run_id)
    if not run:
        raise HTTPException(404, "unknown run_id")
    result: PipelineResult = run["result"]
    if index < 0 or index >= len(result.pending_actions):
        raise HTTPException(400, "invalid pending-action index")
    call = result.pending_actions.pop(index)
    return {"rejected": call.model_dump(), "remaining_pending": len(result.pending_actions)}


@app.get("/api/eval-report")
async def eval_report():
    if not REPORT_PATH.exists():
        raise HTTPException(404, "no report yet — run `python eval/run_eval.py`")
    return JSONResponse(json.loads(REPORT_PATH.read_text()))


# Serve the built frontend (frontend/dist) as static files, so the whole app
# — API and UI — can be deployed as a single service with one URL. This is
# a no-op in local dev if you're running the Vite dev server separately
# (`npm run dev`, which proxies /api to this backend); it only activates
# once `npm run build` has produced frontend/dist. Mounted last and at "/"
# so it never shadows the /api/* routes above — FastAPI matches explicit
# routes before falling through to a mount.
FRONTEND_DIST = Path(__file__).parent.parent / "frontend" / "dist"
if FRONTEND_DIST.is_dir():
    app.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="frontend")
