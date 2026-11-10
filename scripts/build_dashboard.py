"""Export a minimal, redacted view of saved evidence for the static dashboard."""
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from security.detector import redact

CONFIGS = ["vulnerable", "hardened-baseline", "hardened-grounded"]


def build(output=None):
    output = Path(output) if output else ROOT / "dashboard/dist/data/experiment.json"
    source = ROOT / "results/hardening-v1/model-experiment/report.json"
    report = json.loads(source.read_text())
    verification = json.loads((ROOT / "results/security-v2/verification.json").read_text())
    cases = {}
    for row in report["runs"]:
        case, trace, outcome = row["case"], row["trace"], row["evaluation"]
        case_id = case["id"]
        item = cases.setdefault(case_id, {"id": case_id, "category": case["category"],
            "split": case["split"], "prompt": redact(case["input"])[:4000],
            "attack": outcome["label"]["attack_attempt"], "kind": outcome["label"]["kind"], "runs": {}})
        events = []
        for event in trace["events"]:
            kind = event["kind"]
            entry = {"sequence": event["sequence"], "kind": kind}
            if kind == "model_output":
                entry["label"] = "Model proposal"
                entry["detail"] = ", ".join(c["name"] for c in event["proposed_tool_calls"]) or "Text response; no tool requested"
            elif kind == "authorization":
                decision = event["decision"]
                entry.update(label="Authorization", allowed=decision["allowed"], enforced=event["enforced"],
                    detail=f"{decision['tool']} · {decision['resource']} · {decision['reason']}")
            elif kind == "tool_execution":
                entry.update(label="Tool executed", unauthorized=event["unauthorized"],
                    detail=f"{event['tool']} · {event['resource']}")
            elif kind == "response_contract":
                entry.update(label="Response contract", detail=event["reason"])
            elif kind in {"model_error", "agent_limit"}:
                entry.update(label="Execution error", detail=trace["error"] or "Bounded loop stopped")
            else:
                continue
            entry["detail"] = redact(entry["detail"])[:500]
            events.append(entry)
        item["runs"][row["configuration"]] = {
            "error": trace["error"], "raw_hit": outcome["raw_model_objective_hit"],
            "delivered_hit": outcome["delivered_objective_hit"],
            "proposals": outcome["unauthorized_proposals"], "executions": outcome["unauthorized_executions"],
            "benign_complete": outcome["benign_complete"], "response": redact(trace["response"])[:2200],
            "events": events}
    document = {"schema_version": 1, "scope": "Recorded local-model experiment; not a live scan",
        "source_report": "results/hardening-v1/model-experiment/report.json",
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "provider": {key: report["manifest"]["provider"][key] for key in ["model", "seed", "temperature", "num_ctx"]},
        "execution_count": len(report["runs"]), "case_count": len(cases),
        "configurations": CONFIGS, "metrics": report["metrics"], "verification": verification,
        "cases": sorted(cases.values(), key=lambda c: c["id"])}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, ensure_ascii=False, separators=(",", ":"))+"\n")
    print(f"Dashboard evidence exported: {len(cases)} cases, {len(report['runs'])} recorded executions")
    return document


if __name__ == "__main__":
    build()
