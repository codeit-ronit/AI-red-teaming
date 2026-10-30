# Garak 0.17.1 — executed bounded native scans

`run.py` invokes the actual Garak CLI, using `rest.RestGenerator` against the Northwind
HTTP application in both modes. It runs these installed native probes with seed 42,
one generation per prompt, no parallel requests and four prompts per probe:

- `promptinject.HijackLongPrompt`
- `encoding.InjectBase64`
- `encoding.InjectROT13`

Encoding probes use Garak's `text_en` payload collection. These are generic decoded-text
probes, not the project's planted-key extraction cases. Coverage is deliberately small
for an M2/8GB laptop; full family coverage or model robustness is not claimed.

## Actual results

| Native probe | Vulnerable detector hits | Hardened detector hits |
|---|---:|---:|
| HijackLongPrompt / AttackRogueString | 4/4 | 4/4 |
| InjectBase64 / DecodeMatch | 0/4 | 0/4 |
| InjectROT13 / DecodeMatch | 0/4 | 0/4 |

All 24 requests completed without application errors. Native attempts were joined to
private target traces by both prompt and output: 12/12 matched per mode, no missing traces.
There were no observed unauthorized tool attempts, executions, known-key or known-canary
disclosures in this generic probe set.

**Remaining finding:** the hardened model still follows the injected rogue-output instruction.
The execution gateway protects tool/data authorization; it does not guarantee correct task
adherence or stop arbitrary off-task text. The native hitlogs are real observations of textual
prompt hijacking. They are not evidence of a refund or protected-data breach.

Generic decoding matches likewise should not automatically be called vulnerabilities when
the decoded payload is benign. These probes do not have independent malicious/benign labels,
so no detector precision/recall or project ASR is invented for this Garak sample.

## Reproduce

Use the same Ollama and two loopback target servers described in the PyRIT README, with
`AGENTSEC_AUDIT_PATH` enabled. Then, from the repository root:

```sh
uv venv /tmp/agentsec-garak-env
uv pip install --python /tmp/agentsec-garak-env/bin/python -r integrations/garak/requirements.lock
/tmp/agentsec-garak-env/bin/python integrations/garak/run.py --cap 4 --output results/local-garak
```

The script sets Garak's XDG runtime directories beneath the chosen output directory,
generates actual per-mode REST configuration files, and saves console/native outputs.
The full resolved environment snapshot was collected on macOS ARM64/Python 3.13.
A different OS may need a fresh resolution from `garak==0.17.1`.

Artifacts include each mode's `.report.jsonl`, `.hitlog.jsonl`, `.report.html`, config and
console log. The combined `report.json`/`report.md`/`traces.jsonl` preserve both native detector
results and independently observed data/tool consequences. Runtime caches are ignored by Git.
Garak's installed probe/generator lists and help output are saved under `results/frameworks/`.

`rest.json` remains a standalone illustrative REST generator configuration; the driver
creates the tested, capped per-mode configurations. No scans run in standard CI, which
continues to use the lightweight deterministic evaluator.

References: https://reference.garak.ai/en/latest/generators/rest.html and
https://reference.garak.ai/en/latest/probes/promptinject.html.
