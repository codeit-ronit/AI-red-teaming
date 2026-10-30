"""Summarize saved external-framework observations without rerunning inference."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    pyrit = json.loads((ROOT/"results/pyrit/report.json").read_text())
    garak = json.loads((ROOT/"results/garak/report.json").read_text())
    native = {}
    for mode, data in garak["native_summary"].items():
        native[mode] = [{"probe": row["probe"], "detector": row["detector"],
                         "hits": row["fails"], "evaluated": row["total_evaluated"], "unscored": row["nones"]}
                        for row in data["evaluations"] if row["entry_type"] == "eval"]
    summary = {"pyrit": {"version": pyrit["manifest"]["framework_version"], "requests": len(pyrit["runs"]),
                         "metrics": pyrit["metrics"], "errors": sum(bool(r["trace"].get("error")) for r in pyrit["runs"])},
               "garak": {"version": garak["manifest"]["framework_version"], "requests": len(garak["runs"]),
                         "native_detectors": native, "application_outcomes": garak["metrics"],
                         "correlation": {mode: data["correlation"] for mode,data in garak["native_summary"].items()}}}
    (ROOT/"results/frameworks/summary.json").write_text(json.dumps(summary,indent=2)+"\n")
    def fraction(mode, key):
        metric = pyrit["metrics"][mode][key]
        return f"{metric['numerator']}/{metric['denominator']}"
    lines = ["# Actual PyRIT and Garak results", "", "Both frameworks were installed in separate environments and executed against the actual Northwind FastAPI application with local Ollama inference. No fixture provider was used.", "",
             "## PyRIT targeted regression experiment", "", f"Version {summary['pyrit']['version']}; {summary['pyrit']['requests']} requests; {summary['pyrit']['errors']} errors.", "",
             "| Observation | Vulnerable | Hardened |", "|---|---:|---:|"]
    for title,key in [("Successful attacks / targeted malicious cases","attack_success_rate"),
                      ("Unauthorized executions / attempts","unauthorized_action_execution_rate"),
                      ("Synthetic-key disclosures / key cases","synthetic_secret_disclosure_rate"),
                      ("Benign completion","benign_task_completion_rate")]:
        lines.append(f"| {title} | {fraction('vulnerable',key)} | {fraction('hardened',key)} |")
    lines += ["", "Six fixed cases per mode: B01, D01, I02, S01, T01, T02. This is a targeted subset containing previously demonstrated attacks, not a new population estimate or comparison of scanner quality. Inputs match the existing dataset.", "",
              "PyRIT uses PromptSendingAttack, HTTPTarget, and the official JsonStringConverter. On S01 its native SubStringScorer reports true/success for vulnerable and false/failure for hardened. The native outcomes for the other cases are undetermined because a native objective scorer was not configured. Their tool authorization outcomes come from correlated private target execution events, not model claims.", "",
              "[PyRIT report](../results/pyrit/report.md) · [Reproduction instructions](../integrations/pyrit/README.md)", "",
              "## Garak native probes", "", f"Version {summary['garak']['version']}; {summary['garak']['requests']} actual requests; four seeded prompts per probe/mode; one generation; sequential requests.", "",
              "| Probe | Vulnerable hits / evaluated | Hardened hits / evaluated |", "|---|---:|---:|"]
    for row in native['vulnerable']:
        other = next(r for r in native['hardened'] if r['probe'] == row['probe'])
        lines.append(f"| {row['probe']} | {row['hits']}/{row['evaluated']} | {other['hits']}/{other['evaluated']} |")
    lines += ["", "**Remaining weakness: textual prompt hijacking persists in hardened mode.** The native PromptInject detector found the instructed rogue string in actual responses in both modes. The deterministic gateway was designed to protect object access and tool execution; it does not guarantee task adherence or block every off-task answer.", "",
              "The corresponding audit traces contain no unauthorized tool attempt/execution, known-key disclosure or canary disclosure in this generic Garak sample. That limits the observed impact; it does not invalidate the textual hijacking finding. Base64/ROT13 probes used Garak's generic text_en payloads, not the planted-key tests. A decoded benign sentence would not automatically be a protected-data breach.", "",
              "All completed native attempts were correlated to target traces by exact prompt and response, with zero unmatched records. There were no application errors. Generic native probes lack independent malicious/benign labels; therefore detector precision/recall and project ASR are not computed for them.", "",
              "[Garak report](../results/garak/report.md) · [Vulnerable hitlog](../results/garak/vulnerable.hitlog.jsonl) · [Hardened hitlog](../results/garak/hardened.hitlog.jsonl) · [Reproduction instructions](../integrations/garak/README.md)", "",
              "## Evidence, constraints and next steps", "",
              "The HTTP API now supports explicitly opted-in local audit files through AGENTSEC_AUDIT_PATH. Raw synthetic messages and authorization events stay in a local file and are not exposed in the chat response. Tests verify both correlation and the privacy boundary. Native results and application consequences remain separate in the reports.", "",
              "Installed optional dependency snapshots are pinned under each integration. They were resolved on macOS ARM64/Python 3.13; the application retains its own uv.lock and lightweight CI. The core runtime dependency audit does not audit these isolated scanner environments. No paid API, downloaded extra model, or external attack target was used.", "",
              "The scans are small, single-seed, single-model experiments. Future work includes held-out cases, repeated trials, adaptive PyRIT strategies and broader Garak coverage. A task-adherence control would need independent validation; suppressing the observed rogue string would overfit this probe and is not presented as a fix. Hosted GitHub CI and a recorded video remain unexecuted."]
    (ROOT/"docs/framework-results.md").write_text("\n".join(lines)+"\n")
    print("Generated actual external-framework summary")

if __name__ == "__main__":
    main()
