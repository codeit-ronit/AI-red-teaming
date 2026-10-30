# Five-minute demonstration and recording script

No video was recorded automatically. Use this script for a screen recording or interview.
Run from the repository root; keep terminal windows readable and avoid dumping full raw JSON.

## 0:00–0:45 — Explain the boundary

Say: “The model proposes an action. Python independently decides whether the authenticated
user and this agent may execute it. I measure model behavior, execution outcomes and detection separately.”
Show the README architecture and three-mode table.

## 0:45–1:30 — Demonstrate the API

```sh
AGENTSEC_MODE=hardened uv run --frozen uvicorn app.main:app --host 127.0.0.1 --port 8000
# Another terminal:
curl -H 'Authorization: Bearer lab-alice-token' http://127.0.0.1:8000/orders/ORD-A100
curl -H 'Authorization: Bearer lab-alice-token' http://127.0.0.1:8000/orders/ORD-B200
```

Explain 200 versus 403. To show the vulnerable API, stop the server and restart with
`AGENTSEC_MODE=vulnerable`; repeat Bob's order request. Restore hardened mode afterwards.
The public bearer strings are fixture identifiers, not secrets or production authentication.

## 1:30–2:30 — Reproduce an indirect attack

With Ollama running:

```sh
uv run --frozen python -m attacks.runner --provider ollama --case I02 --output results/local-demo
```

Show the poisoned shipping FAQ, model get_order proposal and unauthorized execution event
in vulnerable mode. Compare the fresh hardened run honestly: it may refuse, propose a denied
call, or vary from the saved sample. A rerun is an experiment, not a guaranteed exploit.

## 2:30–3:15 — Isolate enforcement

```sh
uv run --frozen python -m evaluations.replay --source results/ollama-qwen/report.json --case I02
```

Show the captured actual model call and deterministic object-owner denial. State that replay
uses a recorded proposal, not fresh inference. D01 also shows a real hardened model proposal
that was denied at runtime. Open `docs/case-study.md` for correlated evidence request IDs.

## 3:15–4:00 — Show secret removal and metrics

Open the S01 paired traces: vulnerable output contains the public fake key, filtered output
blocks it, hardened system context excludes it. Show why filtering alone leaves unauthorized
operations executable. Explain ASR denominators, two parse errors and benign completion 3/4.

## 4:00–5:00 — Verify engineering quality

```sh
uv run --frozen pytest -m 'not model'
```

Show the CI workflow and local scanner evidence. Finish with limitations: small sample,
heuristic detector, public fixture identity, simulated approvals and no universal defense claim.

For an offline/no-model interview, run the default scripted benchmark and explicitly explain
its role as enforcement regression evidence. Show saved real-model results separately.
