# Promptfoo integration

Pinned CLI: 0.125.1; requires Node >=22.22.0; Python provider interface follows https://www.promptfoo.dev/docs/providers/python/.
The provider invokes the actual Northwind Agent, Ollama adapter and authorization gateway in-process.
It does not bypass application policy or substitute fixture output. Full traces go to
`results/promptfoo-traces.jsonl`. The generated dataset is a subset of `attacks/scenarios.json`.

From the repository root, with Ollama running:

```sh
npm ci --prefix integrations/promptfoo
export PROMPTFOO_PYTHON="$(pwd)/.venv/bin/python"
export PROMPTFOO_DISABLE_TELEMETRY=1
npm --prefix integrations/promptfoo run eval
```

Expected security assertion failures in the vulnerable provider are baseline findings; do not
change them into passes. Provider errors and task-completion failures are separate issues.
The configuration uses deterministic local assertions, no paid LLM judges, and concurrency one.
These are curated adversarial evaluations, not Promptfoo's model-generated redteam campaign.

Verified local run: eight actual-model evaluations; five assertions passed, three failed,
zero provider errors. All three failures are vulnerable-provider security boundary failures;
all four hardened-provider assertions passed. See `results/promptfoo.json`. The earlier
assertion-syntax error is preserved separately and excluded from this result.
