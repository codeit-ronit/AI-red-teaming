"""Shared helpers for opt-in external framework runs against the controlled HTTP targets."""
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import httpx
from evaluations.metrics import aggregate

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {"vulnerable": "http://127.0.0.1:8001", "hardened": "http://127.0.0.1:8002"}


def read_traces(mode):
    path = Path(os.environ.get("AGENTSEC_FRAMEWORK_AUDIT_DIR", str(ROOT/"results/frameworks"))) / f"target-{mode}.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def trace_for(mode, request_id):
    return next(t for t in reversed(read_traces(mode)) if t.get("request_id") == request_id)


def manifest(framework, framework_version):
    with httpx.Client(timeout=15, trust_env=False) as client:
        targets = {}
        for mode, url in TARGETS.items():
            response = client.get(url + "/health")
            response.raise_for_status()
            targets[mode] = response.json()
            if targets[mode]["mode"] != mode:
                raise ValueError("Target mode mismatch")
        response = client.get("http://127.0.0.1:11434/api/tags")
        response.raise_for_status()
        model_metadata = response.json()
    return {"framework": framework, "framework_version": framework_version, "real_model": True,
            "created_at": datetime.now(timezone.utc).isoformat(), "targets": TARGETS,
            "health": targets, "model_metadata": model_metadata,
            "dataset_sha256": hashlib.sha256((ROOT/"attacks/scenarios.json").read_bytes()).hexdigest(),
            "source_hashes": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                for d in ["app", "security", "integrations"] for p in sorted((ROOT/d).glob("**/*.py"))
                if "node_modules" not in p.parts and "__pycache__" not in p.parts}}


def write_report(rows, directory, metadata, native_summary=None):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    metrics = {}
    for mode in TARGETS:
        selected = [r for r in rows if r["trace"]["mode"] == mode]
        if metadata.get("ground_truth_available", True):
            metrics[mode] = aggregate(selected)
        else:
            metrics[mode] = {"target_requests": len(selected),
                "application_errors": sum(bool(r["trace"].get("error")) for r in selected),
                "observed_boundary_violations": sum(r["outcome"]["attack_success"] for r in selected),
                "unauthorized_attempts": sum(r["outcome"]["unauthorized_attempts"] for r in selected),
                "unauthorized_executions": sum(r["outcome"]["unauthorized_executions"] for r in selected),
                "known_key_disclosures": sum(r["outcome"]["secret_disclosed"] for r in selected),
                "known_canary_disclosures": sum(r["outcome"]["canary_disclosed"] for r in selected),
                "detection_metrics": "Not computed: native generic probes lack independent request-level ground truth"}
    report = {"manifest": metadata, "metrics": metrics, "native_summary": native_summary, "runs": rows}
    (directory/"report.json").write_text(json.dumps(report, indent=2)+"\n")
    (directory/"traces.jsonl").write_text("".join(json.dumps(r)+"\n" for r in rows))
    lines = [f"# {metadata['framework']} local experiment", "", f"Framework version: {metadata['framework_version']}. Actual Ollama inference; synthetic local targets only.", "",
             "Native scanner/scorer output and application security outcomes are separate. A positive text match alone is not a validated authorization failure.", "",
             "| Case | Mode | Framework/application error | Protected data/tool invariant violation | Unauthorized executed / attempted |", "|---|---|---|---|---|"]
    for r in rows:
        o = r["outcome"]
        lines.append(f"| {r['case']['id']} | {r['trace']['mode']} | {r['trace'].get('error') or 'none'} | {o['attack_success']} | {o['unauthorized_executions']}/{o['unauthorized_attempts']} |")
    lines += ["", "## Metrics", "", "```json", json.dumps(metrics, indent=2), "```", "", "## Native framework summary", "", "```json", json.dumps(native_summary, indent=2), "```", "",
              "One seeded sample per input/mode. Curated/bounded coverage only; no universal defense claim. Parse/provider errors remain unresolved, never successful defenses."]
    (directory/"report.md").write_text("\n".join(lines)+"\n")
    return report
