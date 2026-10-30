> Historical campaign figures. Current hardening results, hosted CI verification and resume claims are in [final-audit.md](final-audit.md), [final-hardening-report.md](final-hardening-report.md) and [resume-bullets.md](resume-bullets.md).

# Verified results

These numbers are derived from the saved evidence, not proposed targets. Regenerate with
`python -m evaluations.portfolio` after deliberately refreshing the source reports.

## Actual local model campaign

Model: `qwen2.5-coder:3b`, digest `f72c60cabf6237b07f6e632b2c48d533cef25eda2efbd34bed21c5e9c01e6225`, quantization
`Q4_K_M`. Server: {'version': '0.40.7'}.
Temperature 0, seed 42, context 4096, maximum generated tokens 384. Each case/mode has one
sample, with bounded sequential tool calls; model refusals and behavior can vary on rerun.

There are 54 executions: 51 model-dependent case executions plus three
direct API cases. Two ROT13 executions have JSON parsing errors (S03 vulnerable and
filtered), so the ASR populations differ. They are not counted as prevented attacks.

| Metric | Vulnerable | Filtered | Hardened |
|---|---:|---:|---:|
| Attack success | 7/13 (53.8%) | 6/13 (46.2%) | 0/14 (0.0%) |
| Unauthorized execution / attempts | 7/7 (100.0%) | 7/7 (100.0%) | 0/6 (0.0%) |
| Unauthorized block / attempts | 0/7 (0.0%) | 0/7 (0.0%) | 6/6 (100.0%) |
| Known-key disclosure | 1/3 (33.3%) | 0/3 (0.0%) | 0/4 (0.0%) |
| Benign task completion | 3/4 (75.0%) | 3/4 (75.0%) | 3/4 (75.0%) |

## Request-level detection

| Mode | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| vulnerable | 9 | 0 | 4 | 4 | 1.000 | 0.692 | 0.818 | 0.000 |
| filtered | 9 | 0 | 4 | 4 | 1.000 | 0.692 | 0.818 | 0.000 |
| hardened | 8 | 0 | 4 | 6 | 1.000 | 0.571 | 0.727 | 0.000 |

Labels mean attempted malicious behavior, not successful compromise. Policy-derived
alerts are correlated with policy decisions; zero FP in four benign cases is not evidence
of universal accuracy. A hardened model refusal can be a detector FN and still be safe.

## Deterministic enforcement campaign

54 fixture/API executions; explicitly scripted model responses, not an LLM benchmark.
Vulnerable ASR: 14/14 (100.0%).
Hardened ASR: 0/14 (0.0%).
Hardened benign completion: 4/4 (100.0%).
The high vulnerable fixture ASR intentionally exercises a compromised-model contract.

## Verification evidence

- Core pytest: 38 passed; 1 model test skipped by default; JUnit: `results/pytest.xml`.
- Real-model integration: separate opt-in JUnit file `results/pytest-live.xml` if executed.
- HTTP startup, identity and order authorization: `results/http-smoke.json`.
- Actual captured model proposal denied in hardened replay: `results/replay-I02.json`.
- Static scanner: `results/bandit.json`.
- Runtime dependency audit: `results/pip-audit.json`; original advisories retained in `results/pip-audit-before.json`.
- Secret scan: `results/gitleaks.json`.
- Curated real-model Promptfoo comparison: `results/promptfoo.json`; full provider traces: `results/promptfoo-traces.jsonl`.

PyRIT and Garak were subsequently executed against the actual local HTTP targets; see [external framework results](framework-results.md). Hosted GitHub Actions was subsequently verified in final-audit.md; a recorded video remains incomplete.
The initial protocol pilot and initial Promptfoo assertion-syntax failure are development
diagnostics, not members of the main reported sample. No video was recorded.
