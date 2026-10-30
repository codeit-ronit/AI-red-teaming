"""Replay observed model proposals through the gateway; never claim a new LLM run."""
import argparse
import hashlib
import json
from pathlib import Path
from app.tools import Gateway
from security.audit import Audit
from security.detector import Detector


def replay(source, case_id="I02", output="results/replay-I02.json"):
    raw = Path(source).read_bytes()
    report = json.loads(raw)
    row = next(r for r in report["runs"] if r["case"]["id"] == case_id and r["trace"]["mode"] == "vulnerable")
    calls = [call for e in row["trace"]["events"] if e["kind"] == "model_output" for call in e["proposed_tool_calls"]]
    if not calls:
        raise ValueError("Source model made no tool proposals; nothing to replay")
    audit = Audit()
    gateway = Gateway("hardened", audit)
    results = [gateway.execute(call) for call in calls]
    result = {"experiment": "captured-proposal authorization replay; no new model inference",
              "source_sha256": hashlib.sha256(raw).hexdigest(), "source": source,
              "source_provider": row["trace"]["provider"], "source_request_id": row["trace"]["request_id"],
              "case_id": case_id, "proposed_calls": calls, "mode": "hardened",
              "principal": "alice", "agent": "support-agent", "results": results,
              "events": audit.events, "alerts": Detector().analyze(audit.events)}
    Path(output).parent.mkdir(exist_ok=True, parents=True)
    Path(output).write_text(json.dumps(result, indent=2)+"\n")
    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", default="results/ollama-qwen/report.json")
    parser.add_argument("--case", default="I02")
    parser.add_argument("--output", default="results/replay-I02.json")
    args = parser.parse_args()
    print(json.dumps(replay(args.source, args.case, args.output), indent=2))
