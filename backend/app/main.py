"""FastAPI application entry point.

Run from the backend folder:  uvicorn app.main:app --reload --port 8000
Interactive API docs:         http://localhost:8000/docs
"""

from contextlib import asynccontextmanager
import logging

from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router
from app.config import get_settings
from app.services import investigations
from app.services.investigations import NotFound
from app.services.pcap import CaptureError
from app.services.validation import TargetRejected

log = logging.getLogger("linkguard")


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        if not investigations.list_items():
            investigations.load_sample("dns-unanswered")
            investigations.load_sample("tcp-refused")
            investigations.load_sample("http-503")
            log.info("Default 3 sample investigations seeded for clean starting dashboard.")
    except Exception as e:
        log.warning(f"Could not seed sample investigations: {e}")
    yield


app = FastAPI(
    title="LinkGuard 2.0 - Network Incident Detective",
    version="2.0.0",
    description="Evidence-based network troubleshooting using DNS, TCP/IP and packet analysis. Educational project.",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origins,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)


def _error(status: int, code: str, message: str, details=None) -> JSONResponse:
    body = {"error": {"code": code, "message": message}}
    if details:
        body["error"]["details"] = details
    return JSONResponse(status_code=status, content=body)


@app.exception_handler(TargetRejected)
async def _target_rejected(_: Request, exc: TargetRejected) -> JSONResponse:
    return _error(400, exc.code, exc.message)


@app.exception_handler(CaptureError)
async def _capture_error(_: Request, exc: CaptureError) -> JSONResponse:
    return _error(413 if exc.code == "file_too_large" else 400, exc.code, exc.message)


@app.exception_handler(NotFound)
async def _not_found(_: Request, exc: NotFound) -> JSONResponse:
    return _error(404, "not_found", str(exc))


@app.exception_handler(RequestValidationError)
async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
    fields = [{"field": ".".join(str(p) for p in e["loc"][1:]), "problem": e["msg"]} for e in exc.errors()]
    return _error(422, "invalid_request", "Request validation failed.", fields)


@app.exception_handler(Exception)
async def _unexpected(_: Request, exc: Exception) -> JSONResponse:
    log.exception("unhandled error")
    return _error(500, "internal_error", "Unexpected server error.")


app.include_router(router)

# Mount static frontend build if present for unified production deployment
_dist_candidates = [
    Path(__file__).resolve().parent.parent.parent / "frontend" / "dist",
    Path("/app/frontend/dist"),
]
for _candidate in _dist_candidates:
    if _candidate.is_dir() and (_candidate / "index.html").is_file():
        app.mount("/", StaticFiles(directory=str(_candidate), html=True), name="static")
        log.info(f"Mounted production frontend from {_candidate}")
        break
