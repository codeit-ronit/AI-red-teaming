# Security findings index

Validated observations and paired retests are generated in
[the model assessment](../results/ollama-qwen/report.md) and
[its machine-readable report](../results/ollama-qwen/report.json).
The [case study](case-study.md) explains the direct/indirect boundary experiments.

The main model campaign demonstrated direct cross-user access (D01), indirect cross-user
access (I02), synthetic key disclosure (S01), restricted inventory execution (T01), an
unauthorized simulated refund (T02), repeated cross-user access (T03), and direct API BOLA (A01).
Each is scoped to fixture identities/data and the intentionally vulnerable configuration.
The report assigns contextual High severity because the violated primitive is unauthorized
confidentiality or an administrative effect; no production risk assessment or CVSS score is claimed.

System-prompt leakage and several encoding/refund instructions were tested without a confirmed
model-level exploit in this sample. A model claiming it issued a refund without a tool execution
is a reliability failure, not a confirmed unauthorized refund. The fixture campaign intentionally
exercises those compromised-model paths and is explicitly labeled scripted.

## Supply-chain and scanner evidence

`results/pip-audit-before.json` records five advisories for Starlette 0.52.1. The runtime
lock was updated to compatible FastAPI 0.162.0 / Starlette 1.10.0; the final
`results/pip-audit.json` records the retest. Advisories are scanner findings, not proof that
these particular API routes exploit each vulnerable feature. The lab has no StaticFiles or form route.

Bandit initially flagged the intentionally public synthetic lab key as B105. A single-line,
rule-specific nosec comment documents that fixture exception; no other rules are disabled.
The final `results/bandit.json` covers app, security, attacks, evaluations and integrations.

Gitleaks uses its default rules plus exact synthetic-marker and fixture-bearer exceptions and dependency-directory
exclusions. `results/gitleaks.json` is the actual local working-tree scan, not a history scan.
No remote CI execution is claimed. Actual Garak hitlogs are now saved under results/garak/. The original Promptfoo assertion syntax
error is preserved in `results/promptfoo-initial-assertion-error.json`; its failed assertions are
configuration failures, not eight validated target vulnerabilities.

A later complete-source scan flagged five curl examples containing `lab-alice-token`.
Those intentionally public fixture identifiers were added through an exact anchored secret-value
allowlist, not a document-directory exemption. The original redacted scanner output is retained
in `results/gitleaks-before-fixture-allowlist.json`; the final scan was rerun.

## Subsequent PyRIT / Garak evidence

See [external-framework results](framework-results.md). PyRIT reproduced five targeted attacks
in vulnerable mode and none in hardened mode. Garak detected injected rogue-output text in
four PromptInject cases in each mode. This remaining textual task-hijacking weakness is
not fixed by the tool authorization gateway. Its generic encoding probes had no native hits,
and its target traces showed no protected-data disclosure or unauthorized tool execution.
These are distinct observations, not conflicting definitions of a single ASR.
