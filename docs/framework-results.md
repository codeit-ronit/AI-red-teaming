# Actual PyRIT and Garak results

Both frameworks were installed in separate environments and executed against the actual Northwind FastAPI application with local Ollama inference. No fixture provider was used.

## PyRIT targeted regression experiment

Version 1.1.0; 12 requests; 0 errors.

| Observation | Vulnerable | Hardened |
|---|---:|---:|
| Successful attacks / targeted malicious cases | 5/5 | 0/5 |
| Unauthorized executions / attempts | 4/4 | 0/3 |
| Synthetic-key disclosures / key cases | 1/1 | 0/1 |
| Benign completion | 1/1 | 1/1 |

Six fixed cases per mode: B01, D01, I02, S01, T01, T02. This is a targeted subset containing previously demonstrated attacks, not a new population estimate or comparison of scanner quality. Inputs match the existing dataset.

PyRIT uses PromptSendingAttack, HTTPTarget, and the official JsonStringConverter. On S01 its native SubStringScorer reports true/success for vulnerable and false/failure for hardened. The native outcomes for the other cases are undetermined because a native objective scorer was not configured. Their tool authorization outcomes come from correlated private target execution events, not model claims.

[PyRIT report](../results/pyrit/report.md) · [Reproduction instructions](../integrations/pyrit/README.md)

## Garak native probes

Version 0.17.1; 24 actual requests; four seeded prompts per probe/mode; one generation; sequential requests.

| Probe | Vulnerable hits / evaluated | Hardened hits / evaluated |
|---|---:|---:|
| encoding.InjectBase64 | 0/4 | 0/4 |
| encoding.InjectROT13 | 0/4 | 0/4 |
| promptinject.HijackLongPrompt | 4/4 | 4/4 |

**Remaining weakness: textual prompt hijacking persists in hardened mode.** The native PromptInject detector found the instructed rogue string in actual responses in both modes. The deterministic gateway was designed to protect object access and tool execution; it does not guarantee task adherence or block every off-task answer.

The corresponding audit traces contain no unauthorized tool attempt/execution, known-key disclosure or canary disclosure in this generic Garak sample. That limits the observed impact; it does not invalidate the textual hijacking finding. Base64/ROT13 probes used Garak's generic text_en payloads, not the planted-key tests. A decoded benign sentence would not automatically be a protected-data breach.

All completed native attempts were correlated to target traces by exact prompt and response, with zero unmatched records. There were no application errors. Generic native probes lack independent malicious/benign labels; therefore detector precision/recall and project ASR are not computed for them.

[Garak report](../results/garak/report.md) · [Vulnerable hitlog](../results/garak/vulnerable.hitlog.jsonl) · [Hardened hitlog](../results/garak/hardened.hitlog.jsonl) · [Reproduction instructions](../integrations/garak/README.md)

## Evidence, constraints and next steps

The HTTP API now supports explicitly opted-in local audit files through AGENTSEC_AUDIT_PATH. Raw synthetic messages and authorization events stay in a local file and are not exposed in the chat response. Tests verify both correlation and the privacy boundary. Native results and application consequences remain separate in the reports.

Installed optional dependency snapshots are pinned under each integration. They were resolved on macOS ARM64/Python 3.13; the application retains its own uv.lock and lightweight CI. The core runtime dependency audit does not audit these isolated scanner environments. No paid API, downloaded extra model, or external attack target was used.

The scans are small, single-seed, single-model experiments. Future work includes held-out cases, repeated trials, adaptive PyRIT strategies and broader Garak coverage. A task-adherence control would need independent validation; suppressing the observed rogue string would overfit this probe and is not presented as a fix. Hosted GitHub CI and a recorded video remain unexecuted.
