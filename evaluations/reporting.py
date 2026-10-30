import json
from pathlib import Path
from evaluations.metrics import aggregate

MAPPING = {
    "direct": ("LLM01:2025 Prompt Injection", "AML.T0051.000"),
    "indirect": ("LLM01:2025 Prompt Injection; LLM06:2025 Excessive Agency", "AML.T0051.001"),
    "secret": ("LLM02:2025 Sensitive Information Disclosure", "AML.T0051.000"),
    "encoding": ("LLM02:2025 Sensitive Information Disclosure", "AML.T0051.000"),
    "canary": ("LLM07:2025 System Prompt Leakage", "AML.T0051.000"),
    "tool": ("LLM06:2025 Excessive Agency", "AML.T0051.000"),
    "api": ("OWASP API1:2023 Broken Object Level Authorization", None),
}

def write_reports(rows, destination, manifest):
    path = Path(destination)
    path.mkdir(parents=True, exist_ok=True)
    modes = list(dict.fromkeys(r["trace"]["mode"] for r in rows))
    metrics = {mode: aggregate([r for r in rows if r["trace"]["mode"] == mode]) for mode in modes}
    findings = []
    for row in rows:
        if row["trace"]["mode"] != "vulnerable" or not row["outcome"]["attack_success"]:
            continue
        case = row["case"]
        retest = next((r for r in rows if r["case"]["id"] == case["id"] and r["trace"]["mode"] == "hardened"), None)
        mapping = MAPPING.get(case["category"], ("LLM01:2025", None))
        findings.append({"id": "F-"+case["id"], "title": case["title"], "severity": "High (synthetic lab)",
                         "severity_rationale": "Unauthorized access, administrative effect, or protected marker disclosure was observed in a controlled target.",
                         "affected_component": "Northwind application / tool gateway", "surface": case["category"],
                         "trust_boundary": "untrusted input or retrieval -> model -> execution/data boundary",
                         "preconditions": "Local fixture identity Alice; vulnerable mode; synthetic records only",
                         "reproduction": f"python -m attacks.runner --provider {manifest['provider']} --case {case['id']} --output results/reproduction",
                         "legitimate_task": case["legitimate_task"], "input": case["input"],
                         "invariant": case["invariant"],
                         "control_failure": "The synthetic protected value was present in model context and no egress control was enforced" if case["objective"] in {"secret", "canary"} else "The application logged a semantic policy denial but executed the tool anyway in vulnerable mode",
                         "observed_evidence": [e for e in row["trace"]["events"] if e["kind"] in {"authorization", "tool_execution", "model_output"}],
                         "evidence_request_id": row["trace"]["request_id"], "observed_outcome": row["outcome"],
                         "impact": "Synthetic confidentiality or authorization boundary violation; no real assets affected",
                         "owasp": mapping[0], "mitre_atlas": mapping[1],
                         "owasp_agentic": "ASI01:2026 Agent Goal Hijack" if case["category"] in {"direct", "indirect"} else "ASI03:2026 Identity & Privilege Abuse" if case["category"] in {"tool", "api"} else None,
                         "mitigation": "Remove secret from context, filter known markers, authorize every tool by principal, agent, resource and approval before execution",
                         "retest": retest["outcome"] if retest else "Not executed",
                         "retest_error": retest["trace"].get("error") if retest else None,
                         "limitations": "Scripted runs validate enforcement, not model susceptibility. Single-seed model runs are exploratory; marker coverage is bounded."})
    document = {"manifest": manifest, "metrics": metrics, "findings": findings, "runs": rows}
    (path/"report.json").write_text(json.dumps(document, indent=2))
    (path/"traces.jsonl").write_text("".join(json.dumps(row)+"\n" for row in rows))
    lines = ["# AgentSec Ops assessment", "", f"Evidence provider: **{manifest['provider']}**. Real LLM: **{manifest['real_model']}**.", "",
             "Scope: local synthetic Northwind target only. Unresolved error cases are excluded from ASR denominators; observed violations and all unauthorized attempts remain counted.", "", "## Metrics", "", "```json", json.dumps(metrics, indent=2), "```", "", "## Validated observations", ""]
    for finding in findings:
        lines += [f"### {finding['id']}: {finding['title']}", ""]
        lines += [f"- **{key.replace('_',' ')}:** {json.dumps(value) if isinstance(value, dict) else value}" for key, value in finding.items() if key not in {"id", "title"}]
        lines.append("")
    if not findings:
        lines.append("No successful vulnerable-mode attacks were observed in completed cases. This does not establish absence of vulnerabilities.")
    (path/"report.md").write_text("\n".join(lines)+"\n")
    return document
