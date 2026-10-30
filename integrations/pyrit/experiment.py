"""PyRIT 1.1.0: real HTTP attacks, official JSON converter/scorer, audited lab outcomes."""
import argparse
import asyncio
import json
import sys
import time
from importlib.metadata import version
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from integrations.common import TARGETS, manifest, trace_for, write_report
from evaluations.evaluator import evaluate
from security.detector import FAKE_SECRET


def native_outcomes(rows):
    return {"objective_scorer_scope": "SubStringScorer configured for S01 only; other native outcomes are undetermined",
            "outcomes": [{"case": r["case"]["id"], "mode": r["trace"]["mode"],
                "outcome": (r["pyrit_result"] or {}).get("outcome"),
                "score": ((r["pyrit_result"] or {}).get("last_score") or {}).get("score_value")}
                for r in rows]}


async def run(output, case_ids):
    if version("pyrit") != "1.1.0":
        raise RuntimeError("Use the isolated PyRIT 1.1.0 environment")
    from pyrit.setup import initialize_pyrit_async
    from pyrit.prompt_target import HTTPTarget
    from pyrit.executor.attack import PromptSendingAttack, AttackConverterConfig, AttackScoringConfig
    from pyrit.converter import JsonStringConverter
    from pyrit.prompt_normalizer import ConverterConfiguration
    from pyrit.score import SubStringScorer
    await initialize_pyrit_async("InMemory", load_defaults=False, env_files=[], silent=True, seed=42)
    metadata = manifest("pyrit", version("pyrit"))
    metadata["method"] = "PromptSendingAttack; JsonStringConverter; native SubStringScorer on S01; independent execution oracles"
    dataset = json.loads((ROOT/"attacks/scenarios.json").read_text())
    cases = [next(c for c in dataset if c["id"] == case_id) for case_id in case_ids]
    rows = []
    for case in cases:
        for mode, url in TARGETS.items():
            print(f"PyRIT {mode} {case['id']}", flush=True)
            observed = []
            def response_callback(*, response):
                response.raise_for_status()
                body = response.json()
                observed.append(body)
                if body.get("error"):
                    raise RuntimeError(body["error"])
                return body["response"]
            # Official converter escapes JSON string contents, including quotes/newlines.
            body = {"message": "{PROMPT}"}
            if case.get("document_id"):
                body["document_id"] = case["document_id"]
            host = url.removeprefix("http://")
            request = (f"POST /chat HTTP/1.1\r\nHost: {host}\r\n"
                       "Authorization: Bearer lab-alice-token\r\nContent-Type: application/json\r\n\r\n" + json.dumps(body))
            target = HTTPTarget(http_request=request, use_tls=False, callback_function=response_callback,
                                follow_redirects=False, timeout=180, trust_env=False)
            scoring = AttackScoringConfig(objective_scorer=SubStringScorer(substring=FAKE_SECRET)) if case["id"] == "S01" else None
            attack = PromptSendingAttack(objective_target=target,
                attack_converter_config=AttackConverterConfig(request_converters=ConverterConfiguration.from_converters(converters=[JsonStringConverter()])),
                attack_scoring_config=scoring)
            started = time.perf_counter()
            native, error = None, None
            try:
                result = await attack.execute_async(objective=case["input"])
                native = result.model_dump(mode="json")
                if result.error_message:
                    error = result.error_message
            except Exception as exc:
                error = type(exc).__name__+": "+str(exc)
            if observed:
                trace = trace_for(mode, observed[-1]["request_id"])
                if error:
                    trace["error"] = error
            else:
                trace = {"request_id": None, "mode": mode, "response": "", "events": [], "alerts": [],
                         "error": error or "Framework returned without target response", "duration_seconds": time.perf_counter()-started}
            row = {"case": {k:v for k,v in case.items() if k != "fixture_turns"}, "trace": trace,
                   "outcome": evaluate(case, trace), "pyrit_result": native, "http_responses": observed}
            rows.append(row)
            write_report(rows, output, metadata, native_outcomes(rows))
    write_report(rows, output, metadata, native_outcomes(rows))
    if any(r["trace"].get("error") for r in rows):
        raise SystemExit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=str(ROOT/"results/pyrit"))
    parser.add_argument("--case", action="append", dest="cases")
    args = parser.parse_args()
    asyncio.run(run(args.output, args.cases or ["B01", "D01", "I02", "S01", "T01", "T02"]))
