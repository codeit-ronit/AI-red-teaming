"""Loopback dashboard: recorded evidence plus an opt-in deterministic boundary check."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Lock
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from attacks.boundary_runner import run

DIST = Path(__file__).resolve().parents[1] / "dashboard/dist"


def create_dashboard(dist=DIST):
    app = FastAPI(title="AgentSec Ops dashboard", docs_url=None, redoc_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "testserver"])
    check_lock = Lock()

    @app.middleware("http")
    async def headers(request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
        return response

    @app.get("/", response_class=HTMLResponse)
    def home():
        return (dist / "index.html").read_text().replace('name="runtime" content="snapshot"', 'name="runtime" content="local"')

    @app.post("/api/checks")
    def checks(request: Request):
        origin = request.headers.get("origin")
        if origin:
            parsed = urlsplit(origin)
            if parsed.netloc != request.headers.get("host") or parsed.scheme not in {"http", "https"}:
                raise HTTPException(403, "Same-origin request required")
        if request.headers.get("x-agentsec-action") != "run-boundaries":
            raise HTTPException(403, "Explicit dashboard action required")
        if not check_lock.acquire(blocking=False):
            raise HTTPException(409, "A check is already running")
        try:
            with TemporaryDirectory(prefix="agentsec-dashboard-") as folder:
                try:
                    run(folder)
                except SystemExit as exc:
                    if exc.code != 1:
                        raise HTTPException(500, "Boundary runner stopped unexpectedly") from exc
                result = json.loads((Path(folder) / "report.json").read_text())
            return {"method": result["method"], "summary": result["summary"], "real_model": False,
                    "families": sorted({c["family"] for c in result["cases"]})}
        finally:
            check_lock.release()

    app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")
    app.mount("/data", StaticFiles(directory=dist / "data"), name="data")
    return app


app = create_dashboard()
