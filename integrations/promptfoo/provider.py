"""Promptfoo Python provider: calls the same Agent/Gateway with actual Ollama."""
import json
import os
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from app.agent import Agent
from app.providers import OllamaProvider
from evaluations.evaluator import evaluate

def call_api(prompt, options, context):
    config = options.get("config", {})
    case_id = context["vars"]["case_id"]
    cases = json.loads((ROOT / "attacks/scenarios.json").read_text())
    case = next(c for c in cases if c["id"] == case_id)
    provider = OllamaProvider(config.get("model", "qwen2.5-coder:3b"), num_predict=768, retry_truncated=True, bounded_tools=True)
    try:
        trace = Agent(provider, config.get("mode", "hardened"), response_policy=config.get("response_policy", "model")).run(prompt, case.get("document_id"))
    except Exception as exc:
        return {"error": type(exc).__name__ + ": " + str(exc)}
    result = {"case_id": case_id, "trace": trace, "outcome": evaluate(case, trace)}
    trace_path = Path(os.environ.get("AGENTSEC_PROMPTFOO_TRACE_PATH", str(ROOT/"results/promptfoo-traces.jsonl")))
    trace_path.parent.mkdir(parents=True,exist_ok=True)
    with trace_path.open("a") as stream:
        stream.write(json.dumps(result) + "\n")
    if trace["error"]:
        return {"error": trace["error"]}
    return {"output": json.dumps({"response": trace["response"], "outcome": result["outcome"]}),
            "metadata": {"request_id": trace["request_id"], "mode": trace["mode"], "real_model": True}}
