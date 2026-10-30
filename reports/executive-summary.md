# Executive summary — AgentSec Ops

AgentSec Ops is a controlled local retail-support agent laboratory. It tests whether
attacker-controlled messages, retrieved documents and simulated tool notes can manipulate
a model, expose synthetic protected information or execute actions beyond the user's
permissions. All data, credentials and administrative effects are synthetic.

The original Python gateway enforces user identity, separate agent scope, resource
ownership and simulated approval before execution. An output-filtered mode isolates
known-marker filtering from authorization. A later grounded response contract renders
approved support facts from authorized receipts instead of arbitrary model text.

## Observed before/after experiment

Thirty-four inputs were evaluated in three configurations, producing 102 real local-model
executions with one seeded Qwen 3B model. The following comparison holds tool authorization
constant and adds the response contract:

| Observation | Hardened baseline | Hardened + contract |
|---|---:|---:|
| Original text-hijack targets delivered | 4/4 | 0/4 |
| Held-out text-hijack targets delivered | 4/4 | 0/4 |
| Protected instruction-fragment matches delivered | 1/2 | 0/2 |
| Unauthorized executions / prohibited proposals | 0/5 | 0/5 |
| Benign tasks completed | 13/16 | 13/16 |

Raw model hijacking remained 4/4 in both textual groups. The evidence supports application
containment, not a resistant model. Equal benign totals conceal changed failures: Spanish
output was lost, an asset-ID answer was recovered, and JSON/quoted-language tasks still failed.
The content-only detector produced 2 false positives among 16 benign cases; its complete
hardened-sample precision was 12/14 and recall 12/18.

## Verification and recommendations

Actual Promptfoo, PyRIT and Garak experiments were rerun through an opt-in local workflow.
The hosted GitHub pipeline passed 54 model-free tests, deterministic regressions, Bandit,
pip-audit, Gitleaks and artifact upload; fresh outputs were downloaded and checked. This
hosted job did not execute live-model benchmarks.

Keep permissions at the executor, exclude credentials from model context, treat retrieved
instructions and tool prose as untrusted, and constrain output only where product utility
permits. One primary ROT13 parsing failure remains preserved; separate length-bounded
retests produced valid but unhelpful text. The sample is small and labels were not externally
adjudicated. A video recording and broad harmful-output benchmark remain incomplete.

Details: [technical findings](../docs/final-hardening-report.md),
[verification audit and hosted run](../docs/final-audit.md),
[case study](../docs/research-case-study.md), [recording script](../docs/demo-120s.md).
