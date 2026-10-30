# Opt-in local live-model workflow

Standard PR CI remains model-free. This separate local workflow runs actual Promptfoo,
PyRIT and Garak against the application/Ollama, saves commands and native results, and stops
only the two target servers it starts. No paid GPU service or API is required.

Prepare the core environment and isolated framework environments using their existing
pinned requirements. Install Promptfoo with `npm ci --prefix integrations/promptfoo` and
use a Node runtime >=22.22.0. Start `ollama serve` in another terminal and ensure the existing
`qwen2.5-coder:3b` model is installed. Ports 8001/8002 must be free.

From the repository root, using the already prepared local paths on the development machine:

```sh
.venv/bin/python -m integrations.live_workflow \
  --output results/local-live-001 \
  --pyrit-python /tmp/agentsec-pyrit-env/bin/python \
  --garak-python /tmp/agentsec-garak-env/bin/python \
  --node /tmp/agentsec-node/node_modules/node/bin/node
```

Replace executable paths for another machine. Choose a new output directory for every run;
existing nonempty output directories are rejected. The `/tmp` installations are disposable
local environments, not dependencies committed to the repository.

The workflow runs vulnerable + model-output mode and hardened + grounded-response mode.
The target's `/health` records both settings. Promptfoo calls the same core application
in-process; PyRIT and Garak use the actual HTTP targets. Private target JSONL is stored in
the output directory, so historical raw evidence is preserved. Promptfoo provider traces
also use that new directory. Only expected vulnerable assertion failures are accepted;
provider/runtime errors fail the workflow.

Read `summary.json`, `commands.json`, native reports and target traces together. A native
Garak hit is a text-level result; absence of a hit is not proof of model resistance. Inspect
raw model output separately from the delivered grounded response. The PyRIT scorer remains
native on S01; other objective outcomes are independently evaluated from application events.
