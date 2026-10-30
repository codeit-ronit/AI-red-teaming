import argparse
import hashlib
import json
import platform
from datetime import datetime, timezone
from importlib.resources import files
from importlib.metadata import version
from pathlib import Path
from app.agent import Agent
from app.providers import OllamaProvider, ScriptedProvider
from app.tools import Gateway
from evaluations.evaluator import evaluate
from evaluations.reporting import write_reports
from security.audit import Audit
from security.detector import Detector


def run(provider="scripted", model="qwen2.5-coder:3b", modes=("vulnerable", "filtered", "hardened"), case_ids=None, output="results/deterministic", num_predict=384, retry_truncated=False, bounded_tools=False, max_content_chars=None):
    source = files("attacks").joinpath("scenarios.json").read_bytes()
    cases = json.loads(source)
    if case_ids:
        unknown = set(case_ids) - {c["id"] for c in cases}
        if unknown:
            raise ValueError(f"Unknown cases: {unknown}")
        cases = [c for c in cases if c["id"] in case_ids]
    live = OllamaProvider(model, num_predict=num_predict, retry_truncated=retry_truncated, bounded_tools=bounded_tools, max_content_chars=max_content_chars) if provider == "ollama" else None
    metadata = live.describe() if live else {"provider": "scripted", "real_model": False}
    manifest = {"provider": provider, "real_model": provider == "ollama", "model_metadata": metadata,
                "created_at": datetime.now(timezone.utc).isoformat(), "python": platform.python_version(),
                "dataset_sha256": hashlib.sha256(source).hexdigest(), "modes": list(modes),
                "runtime_versions": {name: version(name) for name in ["fastapi", "httpx", "pydantic", "uvicorn"]},
                "source_hashes": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for directory in ["app", "security", "attacks", "evaluations"] for p in sorted(Path(directory).rglob("*.py"))},
                "method": "single seeded sample per case/mode; paired identical attacker inputs"}
    rows = []
    for case in cases:
        for mode in modes:
            print(f"{provider} {mode} {case['id']}", flush=True)
            if case["category"] == "api":
                # Exercise the actual FastAPI route, rather than approximating its behavior.
                from fastapi.testclient import TestClient
                from app.main import create_app
                import time
                api = create_app(mode)
                start = time.perf_counter()
                response = TestClient(api).get("/orders/ORD-B200", headers={"Authorization": "Bearer lab-alice-token"})
                events = api.state.traces[-1]["events"]
                trace = {"request_id": events[0]["request_id"], "mode": mode, "provider": {"provider": "direct-api", "real_model": False},
                         "response": response.text, "events": events, "alerts": Detector().analyze(events), "error": None,
                         "http_status": response.status_code, "duration_seconds": time.perf_counter()-start}
            else:
                adapter = live if live else ScriptedProvider(case["fixture_turns"])
                agent = Agent(adapter, mode)
                try:
                    trace = agent.run(case["input"], case.get("document_id"))
                except Exception as exc:
                    # Preserve failures as failures, never as blocked attacks or model refusals.
                    trace = {"request_id": agent.audit.request_id, "mode": mode, "provider": adapter.metadata.copy(),
                             "response": "", "events": agent.audit.events, "alerts": Detector().analyze(agent.audit.events),
                             "error": type(exc).__name__+": "+str(exc), "duration_seconds": None}
            row = {"case": {k:v for k,v in case.items() if k != "fixture_turns"}, "trace": trace, "outcome": evaluate(case, trace)}
            rows.append(row)
            # Checkpoint after every execution, including model/network failures.
            write_reports(rows, output, manifest)
    return write_reports(rows, output, manifest)


def main():
    parser = argparse.ArgumentParser(description="Controlled local agent security evaluation")
    parser.add_argument("--provider", choices=["scripted", "ollama"], default="scripted")
    parser.add_argument("--model", default="qwen2.5-coder:3b")
    parser.add_argument("--modes", nargs="+", choices=["vulnerable", "filtered", "hardened"], default=["vulnerable", "filtered", "hardened"])
    parser.add_argument("--case", action="append", dest="cases")
    parser.add_argument("--output", default="results/deterministic")
    parser.add_argument("--num-predict", type=int, default=384)
    parser.add_argument("--retry-truncated", action="store_true")
    parser.add_argument("--bounded-tools", action="store_true")
    parser.add_argument("--max-content-chars", type=int)
    args = parser.parse_args()
    report = run(args.provider, args.model, args.modes, args.cases, args.output, args.num_predict, args.retry_truncated, args.bounded_tools, args.max_content_chars)
    print(json.dumps(report["metrics"], indent=2))
    if any(r["trace"].get("error") for r in report["runs"]):
        raise SystemExit(1)

if __name__ == "__main__":
    main()
