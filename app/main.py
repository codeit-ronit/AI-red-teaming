"""Loopback-only synthetic laboratory. Set mode on the server, never in a request."""
import json
import os
from pathlib import Path
from threading import Lock
from typing import Annotated
import httpx
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from app.agent import Agent
from app.models import ChatRequest
from app.providers import OllamaProvider
from app.tools import Gateway, load_data
from security.audit import Audit

# Public fixture credentials are identifiers for this controlled lab, not real secrets.
TOKENS = {"lab-alice-token": "alice", "lab-bob-token": "bob", "lab-admin-token": "admin"}
bearer = HTTPBearer(auto_error=False)

def create_app(mode=None, provider_factory=None, audit_path=None, response_policy=None):
    mode = mode or os.environ.get("AGENTSEC_MODE", "hardened")
    if mode not in {"vulnerable", "filtered", "hardened"}:
        raise ValueError("Invalid server mode")
    response_policy = response_policy or os.environ.get("AGENTSEC_RESPONSE_POLICY", "grounded" if mode == "hardened" else "model")
    if response_policy not in {"grounded", "model"}:
        raise ValueError("Invalid response policy")
    app = FastAPI(title="AgentSec Ops — Northwind laboratory")
    data = load_data()
    app.state.traces = []
    trace_path = audit_path or os.environ.get("AGENTSEC_AUDIT_PATH")
    trace_lock = Lock()
    def record_trace(trace):
        # Explicit opt-in: raw synthetic lab evidence for local scanner correlation.
        # No HTTP route exposes this file or its full traces.
        with trace_lock:
            if trace_path:
                path = Path(trace_path)
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("a") as stream:
                    stream.write(json.dumps(trace) + "\n")
            app.state.traces.append(trace)
            del app.state.traces[:-100]
    def identity(credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]):
        if credentials is None or credentials.credentials not in TOKENS:
            raise HTTPException(401, "Valid lab bearer identity required")
        return TOKENS[credentials.credentials]
    @app.get("/health")
    def health():
        return {"status": "ok", "mode": mode, "scope": "synthetic-local-lab", "response_policy": response_policy}
    @app.post("/chat")
    def chat(body: ChatRequest, principal: str = Depends(identity)):
        provider = provider_factory() if provider_factory else OllamaProvider(os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:3b"), num_predict=int(os.environ.get("AGENTSEC_NUM_PREDICT", "768")), retry_truncated=True, bounded_tools=True)
        try:
            trace = Agent(provider, mode, principal, data=data, response_policy=response_policy).run(body.message, body.document_id)
        except httpx.HTTPError as exc:
            raise HTTPException(503, "Local model unavailable") from exc
        record_trace(trace)
        # No raw prompts, internal canaries, tool results, or other users' traces in response.
        return {key: trace[key] for key in ["request_id", "mode", "response", "error"]}
    @app.get("/orders/{order_id}")
    def order(order_id: str, principal: str = Depends(identity)):
        audit = Audit()
        result = Gateway(mode, audit, principal, data=data).execute({"name": "get_order", "arguments": {"order_id": order_id}})
        record_trace({"events": audit.events})
        if not result["executed"]:
            raise HTTPException(403, "Resource unavailable")
        return result["result"]
    return app

app = create_app()
