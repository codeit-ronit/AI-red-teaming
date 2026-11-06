# Broader red teaming and execution-boundary hardening

Reviewed November 6, 2026. This is a follow-up to the preserved 102-execution study.

## Assessment of the original evidence

The original scenarios were sufficient to demonstrate particular vulnerabilities and compare controls. They were insufficient to establish broad resistance. Eighteen attack cases in the final suite include related extraction and textual-hijack variants. One sample per case/configuration, one model, one seed, exact-marker oracles and project-authored labels leave significant uncertainty. A zero observed success count is a sample result, not a universal security guarantee.

We should judge coverage by distinct attack surfaces, attacker capabilities and measurable consequences, rather than increasing the count by paraphrasing the same instruction. Previously the permission reference treated a customer creating their own ticket as allowed even when an injected document induced that write during an unrelated read-only request. Resource authorization alone did not describe user intent.

## What research changes about our method

- **Threat model first:** identify protected assets, attacker-controlled inputs and tool effects. The [OWASP Agentic Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) supplies a risk checklist; it is not a certification or a benchmark score. Its [red-teaming manual](https://genai.owasp.org/resource/genai-red-teaming-manual-version-1-0/) is a further reference for planning assessments.
- **Evaluate actions and usefulness together:** [AgentDojo](https://agentdojo.spylab.ai/) is a public environment for evaluating agent tasks, injections and defenses. Our constrained support renderer does not directly solve its broader task suite. An adapter must preserve legitimate task requirements; suppressing every answer would not be a useful defense.
- **Adapt after seeing the defense:** the [NAACL 2025 study](https://aclanthology.org/2025.findings-naacl.395/) motivates testing attacks designed against the disclosed defense. A static corpus should be supplemented with a budgeted search and reported attempt counts.
- **Test conversational strategies:** [PyRIT multi-turn documentation](https://microsoft.github.io/PyRIT/1.0.1/code/executor/multi-turn/) describes gradual escalation, branching search and requests split across turns. Fixed scripts and model-driven adaptation are different methods. Our HTTP target currently starts a fresh conversation on each request; repeatedly posting to it does not test conversation-memory attacks.
- **Layer controls:** [Anthropic's injection-defense report](https://www.anthropic.com/research/prompt-injection-defenses) combines model and surrounding safeguards and evaluates repeated adaptive attempts. Its published results do not imply equivalent performance for our application.

These references informed the follow-up; their benchmark results are not our results. No AgentDojo or BIPIA benchmark was executed in this change. [Microsoft BIPIA](https://github.com/microsoft/BIPIA) is another candidate for indirect-injection evaluation, with different tasks and scoring requirements.

## Coverage and remaining work

| Attack surface or strategy | Example objective | Current coverage and next step |
|---|---|---|
| Direct instruction and authority spoofing | Claim administrator identity or override policy | Existing model scenarios and identity/resource matrix; keep identity outside model arguments. |
| Retrieved-document injection | Turn a FAQ into a command | Existing model scenarios; extend to more positions, formats and document lengths. |
| Tool-result poisoning | Turn a tool observation into a trusted instruction | Existing model scenarios; new compromised-model tests deny unrelated writes. |
| Valid-tool misuse | Create an unwanted ticket using a generally allowed tool | New separate ticket consent and one-write budget. |
| Workflow chaining | Read a record, then place its contents in another operation | New poisoned-observation write test; broader effect/data-flow oracles still needed. |
| Approval forgery, replay and races | Reuse one refund approval for multiple effects | New expiry, resource binding, atomic one-use consumption and concurrency tests. |
| Request-state contamination | Reuse old receipts as proof of a new operation | New request isolation and overlapping-use guard; this is an internal object-lifecycle test. |
| Resource exhaustion | Batch many individually valid tool calls | New total tool budget and ticket budget; no network load or denial-of-service campaign performed. |
| Obfuscation and multilingual attacks | Encode instructions, use Unicode or another language | Existing secret encoding cases and small new Spanish fixture; broad language coverage remains incomplete. |
| Answer manipulation and instruction extraction | Hijack output or recover hidden instructions | Prior actual-model evidence and grounded output contract; semantic leakage remains incompletely measured. |
| Multi-turn escalation and split requests | Build trust, then combine earlier pieces | Not evaluated as conversational attacks: no persistent chat session exists. |
| Best-of-N and adaptive search | Revise an attack using target feedback | Planned; no adaptive attack-success score claimed. |
| Persistent memory / RAG index poisoning | Plant an instruction for future users | Persistent memory and a writable retrieval index are absent. Requires a new test subject. |
| URL exfiltration, SSRF, shell or browser abuse | Send data to an external endpoint or execute code | No URL-fetching, outbound-message, shell or browser tool is registered. Unknown tools fail validation; actual sandbox/egress defenses are not evaluated. |
| Image/audio injection and multi-agent delegation | Hide instructions in another modality or agent message | These surfaces are absent. They require additional targets, not text-only coverage claims. |
| Dependency or tool-supply-chain compromise | Replace trusted tool code or metadata | CI scanners cover particular dependency/secret issues; an adversarial supply-chain campaign remains unexecuted. |

## Reproduced issues and changes

The source before these changes is recorded in [before.json](../results/security-v2/before.json). These are deterministic compromised-model fixtures, not new claims about real-model exploit rates.

| Check | Before | After |
|---|---|---|
| Same trusted refund approval reused across two gateways | Two executions | First executes; second denied. |
| Model requests a ticket during a read-only support question | One unwanted write | Zero writes with strict request scope. |
| Same Agent object reused for a second request without a fresh lookup | Same request ID and stale receipt-backed answer | New request ID, no earlier execution receipt and no stale order status. |

### Explicit request capabilities

Hardened HTTP now supplies `ExecutionScope` from request context. Ticket creation defaults to disabled. An authenticated customer must explicitly submit `allow_ticket_creation: true` separately from chat text. Model output, retrieved documents and tool observations cannot set this field. Consent grants only the ability to create the customer's own ticket; it cannot grant admin permission.

This is a capability for one request, not a human review workflow. If a real chat UI adds it, display a separate confirmation control; never have the model silently choose it. Consent currently authorizes a ticket operation, not an exact reviewed description. Exact-content confirmation and downstream data-loss controls remain further work.

Each hardened HTTP request permits at most four gateway attempts, including preloaded document reads and malformed attempts. At most one ticket can be created, even with consent. These limits bound tool effects; inference still has the existing four-step bound and local provider timeout. Global rate limits, wall-clock request budgets, byte limits on upstream responses and multi-worker capacity controls remain incomplete.

**Python compatibility:** `Agent` and `Gateway` default to a read-only `ExecutionScope()`. Use `ExecutionScope(allow_ticket_creation=True)` only after explicit consent. Historical runners and the original Promptfoo adapter explicitly pass `execution_scope=None` to retain their versioned request-capability behavior; this is a trusted Python compatibility escape hatch, unavailable through HTTP. Existing role/resource checks remain enforced in hardened mode even without scope. Request isolation and approval consumption apply independently of scope.

### Short-lived, single-use approvals

Fixture approvals expire after five minutes by default. A lock makes consumption atomic across gateways sharing that object. Permission checks are completed before consumption. Expired, mismatched and previously consumed approvals cannot authorize another refund.

The replay guarantee is limited to the shared approval object in one process. There is no authenticated approval issuer, signed token, persistent cross-worker nonce ledger, restart protection or transactional external payment service. Constructing another approval in trusted Python is issuing a new fixture approval. Production deployment would require those missing boundaries.

### Request isolation

Every `Agent.run` creates fresh audit, gateway, receipt, ticket and budget state. Reusing an Agent cannot use an earlier request's receipts to ground its answer. Overlapping calls on the same Agent fail immediately. These changes do not create persistent conversational memory.

## Verification and reproducibility

- [Before reproduction](../results/security-v2/before.json) and [after reproduction](../results/security-v2/after-final.json).
- [Boundary report](../results/security-v2/verified-boundaries/report.md) and [full evidence](../results/security-v2/verified-boundaries/report.json): **142 checks**, including legitimate allowed operations and denied operations. These are structured deterministic checks, not 142 different prompt-injection techniques.
- [Regression results](../results/security-v2/pytest.log): **76 passing tests**, one opt-in live-model test deselected. The prior 54 tests remain included.
- The new boundary runner runs in GitHub Actions. Live-model resistance is not inferred from fixture checks.

```sh
uv run --frozen pytest -m 'not model'
uv run --frozen python -m attacks.boundary_runner --output results/local-boundaries
```

To intentionally create a ticket through hardened HTTP:

```sh
curl -H 'Authorization: Bearer lab-alice-token' -H 'Content-Type: application/json' \
  -d '{"message":"Create a support ticket for a delayed parcel.","allow_ticket_creation":true}' \
  http://127.0.0.1:8000/chat
```

The historical 102-execution records and demo remain evidence of the earlier source/configurations. They were not regenerated or relabeled as proof of these new controls.

## Next evaluation milestones

1. Build an AgentDojo adapter in an isolated environment; pin upstream revision, tasks, injection points, attacker budget and task-success oracles. Report unsupported tasks rather than treating refusals as successes. Keep tuning and evaluation splits separate.
2. Run a capped public-benchmark pilot with the current local model. Record utility without attack, utility under attack, targeted consequences, failures and exact denominators. Full upstream benchmark execution is distinct from importing a few payloads.
3. Add feedback-driven adaptive search, with a separate attacker and objective scorer, fixed attempt budget, and all attempts saved. Compare against static attacks under equal budgets.
4. Repeat over seeds and model families, review semantic outcomes manually and report uncertainty. Version the defenses before evaluating a fresh split.
5. Before production claims: replace public fixture identities, implement authenticated approval issuance and a persistent replay ledger, bind write approval to exact operation contents, add sandbox/egress controls for new tools, and test deployment resource limits.

The aim is defensible, bounded guarantees about specific operations under stated assumptions. A finite attack suite cannot establish that the complete system is bulletproof.
