# Architecture and engineering decisions

## Original contribution

The core contribution is the Python authorization gateway and its auditable comparison
with model proposals, actual execution, detector alerts and outcome oracles. Third-party
frameworks supply additional entry points; they do not replace this logic.

| Decision | Reason | Cost / consequence |
|---|---|---|
| Python + FastAPI + Pydantic | Small typed API and strict structured tool interface | Schemas do not supply authorization |
| Ollama + existing 3B Q4_K_M model | Zero API cost and fits the existing M2/8GB environment | Coding model has limited agent reliability |
| JSON-schema generation protocol | Works without native tool-call support | Parse/truncation errors must remain visible |
| In-memory fixture objects | Reproducible isolated controlled effects | Tickets/refunds reset with each gateway/request |
| Separate principal and agent | Prevent user identity from implicitly granting agent privileges | Policy must allow both identities |
| Server-side fixed mode | Attacker cannot disable controls through the request | Restart server to compare API modes |
| Three modes | Isolate output filtering from independent authorization | Hardened mode also removes the key, so model behavior may change |
| Shadow authorization in vulnerable mode | Label real bypasses with the same policy as hardened mode | Shares policy code with enforcement; manually validate policy semantics |
| Schema validation in every mode | Avoid arbitrary Python execution or accidental scope expansion | Vulnerable mode only demonstrates selected semantic control failures |
| Read-only shared fixtures, request-local effects | Avoid state contamination between paired tests | Not a production transactional backend |
| Bounded 4-step loop, at most 4 calls/turn | Limit resource use and repeated effects | Long legitimate workflows can be incomplete |
| Event-based heuristic detector | Explainable, testable, independent from blocking | Easy to evade; policy-derived alerts are not independent proof of attack intent |
| Deterministic outcome oracles | Measure actual tools and planted marker emissions | Do not judge all unsafe text or semantic leakage |
| Scripted provider + actual model adapter | Fast CI and honest model susceptibility evidence | Fixture success must not be called LLM ASR |
| Lockfile + local venv | Reproducible dependencies without altering system packages | Locks must be refreshed when advisories change |
| Sequential local inference | Keeps memory and runtime manageable on M2 | Lower benchmark throughput |

## Request flow

1. FastAPI resolves a public fixture bearer token to an explicit principal.
2. Server chooses mode and the support-agent identity. Chat JSON contains only a message and optional document ID.
3. An optional support document is fetched through the same gateway; its text is labeled untrusted.
4. The provider receives the actual system/user/retrieval messages and returns a strict JSON object.
5. Every proposed tool call passes registry and argument validation, then authorization.
6. A denied hardened call produces a denial result without executing the tool. Vulnerable/filtered modes record the same policy decision and intentionally bypass it.
7. Tool results return to the agent as untrusted data, within a bounded loop.
8. Protected markers are filtered from the final user-visible response where configured.
9. The evaluator stores synthetic raw messages, events, decisions and outputs; chat users only receive response/request ID/mode/error.
10. The detector consumes events after execution. The evaluator scores policy consequences and detection separately.

## Policy precedence

Deny unknown principal → deny unknown tool/agent → deny tool/action outside agent scope →
check object existence and owner → check inventory/document scope → check administrative role →
check object-bound approval → allow. Every branch returns a structured reason and policy ID.

The support-agent cannot use admin_refund_order even if its user is admin. The refund-agent
is a distinct fixture identity; it still needs an admin principal and a matching Approval.
The chat endpoint never accepts a caller-provided agent or Approval object.

## Code walkthrough

- `app/main.py`: HTTP identity boundary, server mode, health, chat and order route.
- `app/agent.py`: system context, retrieval, bounded proposal/result loop, output filter.
- `app/providers.py`: actual Ollama adapter and explicitly scripted fixture adapter.
- `app/tools.py`: strict per-tool schema validation, shadow/enforced decisions, controlled effects.
- `security/authorization.py` and `policies.py`: least-privilege authorization and registry.
- `security/approvals.py`: immutable bound simulation of trusted reviewer approval.
- `security/audit.py`: timestamps, request IDs and monotonically numbered events.
- `security/detector.py`: transparent event rules and bounded marker transformations.
- `attacks/scenarios.json`: version-controlled inputs, invariants, labels, fixture responses.
- `attacks/runner.py`: paired execution, checkpoints, model/config metadata, error capture.
- `evaluations/evaluator.py`: consequence-based oracles; model claims alone do not establish success.
- `evaluations/metrics.py`: denominators, confusion matrix and aggregate metrics.
- `evaluations/reporting.py`: JSON/JSONL/Markdown findings with paired retests and taxonomy.
- `evaluations/replay.py`: replay actual captured proposals without generating new model behavior.

## Storage and audit limitations

Benchmark JSONL is durable evidence, not an append-only audit database. HTTP traces are bounded
to the latest 100 requests in process memory and have no public read endpoint.
An explicit AGENTSEC_AUDIT_PATH configuration additionally appends private synthetic traces
to a local JSONL file under a process-local lock, allowing native scanner/target correlation. IDs and timestamps
support correlation; they do not prevent tampering. Complete raw traces are intentionally retained
only because every asset is synthetic. Production traces would require minimization, authorization,
redaction, retention rules, durable storage and integrity controls.
