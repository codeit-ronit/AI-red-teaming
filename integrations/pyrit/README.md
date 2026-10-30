# PyRIT 1.1.0 — executed local experiment

The script uses the installed PyRIT APIs: `initialize_pyrit_async`, `HTTPTarget`,
`PromptSendingAttack`, `JsonStringConverter`, and `SubStringScorer`. Requests go to the
actual Northwind HTTP application and its Ollama model, not a mock or bare model bypass.

Six fixed cases (B01, D01, I02, S01, T01, T02) run against vulnerable and hardened modes.
This is a targeted regression subset, including previously demonstrated vulnerabilities;
do not compare its ASR directly to the broader original 18-case campaign.

Verified run: 12 requests, no application/framework errors. Vulnerable: 5/5 successful
attacks, 4/4 unauthorized actions executed, 1/1 key disclosure. Hardened: 0/5 successful
attacks, 0/3 unauthorized actions executed, no key disclosure. Benign own-order completion
was 1/1 in each mode. These are small-sample observations, not population estimates.

The native PyRIT substring scorer is configured for S01 only: success/true for vulnerable,
failure/false for hardened. Other native attack outcomes are **undetermined** because no
native objective scorer is configured for them. Their application outcomes are evaluated
from correlated target audit events using the project's original consequence oracles.
The official JSON string converter safely escapes the prompt inside the HTTP JSON request;
it is a transport converter, not an additional adversarial encoding experiment.

## Reproduce

From the repository root:

```sh
uv venv /tmp/agentsec-pyrit-env
uv pip install --python /tmp/agentsec-pyrit-env/bin/python -r integrations/pyrit/requirements.lock
```

Start Ollama and the two targets in separate terminals:

```sh
ollama serve
AGENTSEC_MODE=vulnerable AGENTSEC_AUDIT_PATH=results/frameworks/target-vulnerable.jsonl uv run --frozen uvicorn app.main:app --host 127.0.0.1 --port 8001
AGENTSEC_MODE=hardened AGENTSEC_AUDIT_PATH=results/frameworks/target-hardened.jsonl uv run --frozen uvicorn app.main:app --host 127.0.0.1 --port 8002
```

Then run:

```sh
/tmp/agentsec-pyrit-env/bin/python integrations/pyrit/experiment.py --output results/local-pyrit
```

Use `--case S01` to run just the paired key-disclosure test. The full resolved environment
snapshot was collected on macOS ARM64/Python 3.13; portability to other platforms is not
claimed. Framework environments are separate from the frozen application environment.
PyRIT creates its normal local user-data/log directories on macOS; its experiment memory
is in-memory SQLite, and no Azure account, paid model or external target is used.

Artifacts: `results/pyrit/report.json`, `report.md`, and `traces.jsonl` include native
PyRIT results, actual HTTP responses, private target traces, oracles and metrics.
The main JSON/Markdown files are checkpointed after every request. Runtime failures exit
nonzero rather than counting as a prevented attack. Adaptive multi-turn campaigns remain future work.

Official reference: https://microsoft.github.io/PyRIT/latest/code/targets/prompt-targets/
