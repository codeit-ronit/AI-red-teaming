# Is τ²-bench useful for AgentSec Ops?

Reviewed November 9, 2026. **Yes: use it as a second, external test environment and legitimate-task benchmark, with a separately defined security evaluation.** This assessment inspected public data and code; no benchmark was installed or executed and no performance score was measured.

## What it provides

The [original paper](https://arxiv.org/abs/2506.07982) studies conversations, tool use and policy following. In its telecom domain, the simulated customer also controls tools, such as changing phone settings. The support agent must coordinate its own operations with the customer's actions. That is the meaning of dual control; it is not a defender/attacker pair by definition.

It is an executable environment rather than a spreadsheet of prompts. It includes synthetic databases, business policies, callable tools, task definitions, simulated customers and evaluators. A separate language-model role simulates the customer. Our security framework could run around this environment, but the original task-success score alone would not establish resistance to prompt injection.

## Data actually inspected

Official repository revision: [`033bf082f48e4a3c6a1256208e93cf2ce9c3bb6f`](https://github.com/sierra-research/tau2-bench/tree/033bf082f48e4a3c6a1256208e93cf2ce9c3bb6f). The repository has evolved beyond the original paper, so a future experiment must also pin the relevant released data/benchmark configuration. The following counts describe these files, not every newer benchmark pack.

| Domain | Task-file records | Named splits inspected |
|---|---:|---|
| Retail | 114 | train 74; test 40; base 114 |
| Airline | 50 | train 30; test 20; base 50 |
| Telecom | 2,285 | small 20; train 74; test 40; base 114; full 2,285 |

Splits overlap by design; do not add them together. Telecom's 114-task base and its expanded full pool are different populations. The [inspection manifest](tau2-data-inspection.json) records counts and downloaded-file hashes. No upstream task files are copied into this project.

A task contains:

- `user_scenario`: the customer's problem, information they know and constraints.
- `initial_state`: optional starting database changes or prior messages.
- `evaluation_criteria`: expected actions, communication requirements, state assertions and the selected reward basis.
- An ID and description, with additional fields varying by domain.

For example, retail task 0 concerns a customer exchanging two delivered products while specifying acceptable replacement variants. Its reference actions include identity lookup, order/product queries and an exchange. The telecom sample concerns a traveler with unusable mobile data; its starting state and checks cover roaming and actual connectivity. These are paraphrased examples from the inspected task files, not newly executed AgentSec scenarios.

The [retail policy](https://github.com/sierra-research/tau2-bench/blob/033bf082f48e4a3c6a1256208e93cf2ce9c3bb6f/data/tau2/domains/retail/policy.md) requires customer identification, one customer per conversation and explicit confirmation before database-changing operations. Identity lookup in a synthetic benchmark is not production authentication.

## Recommended build

Build a **τ² retail adapter for AgentSec Ops**, keeping the upstream simulator and task evaluation. Add our trace format, operation authorization, confirmation binding and attack-consequence scoring around the real execution boundary.

Run four conditions on the same eligible tasks:

| Condition | What it answers |
|---|---|
| Original agent, clean task | Can the model do the job at all? |
| Defended agent, clean task | How much legitimate functionality do our controls cost? |
| Original agent, attacked task | Can the chosen adversary achieve a specific forbidden consequence? |
| Defended agent, same attacked task | Does the defense contain that consequence while preserving the legitimate objective? |

A pilot could use five preselected retail training tasks, one attack variant per task and one trial: 20 conversation episodes across those conditions. Episodes include many model calls; this is not a 20-request estimate or a full benchmark result. Freeze the adapter and policy before evaluating the held-out split. Repeat trials later to measure reliability; choose tasks before seeing outcomes and report errors separately.

Potential attack objectives include switching to another customer's order mid-conversation, forging confirmation, changing an unconfirmed shipping address, repeating an approved mutation or laundering instructions through a tool result. These are proposed extensions. Each must specify the attacker-controlled surface, attack budget, protected identity/operation and an independent success check. Confirm that the selected task actually exposes the surface; preserve canonical clean tasks and version altered cases separately.

## Necessary engineering work

1. **Agent interface:** implement the upstream turn-based agent interface and map messages/tool proposals to AgentSec events. Our existing `/chat` creates a fresh conversation on every request. Add bounded episode state scoped to one simulated customer; preserve isolation across episodes.
2. **Execution interface:** wrap tool execution and result delivery. Retail exposes 16 tools, compared with our five registered Northwind tools. Names, argument schemas, databases and operation semantics differ; renaming a function is insufficient.
3. **Policy adapter:** bind the identified simulated customer to resource ownership and allowed operations. Track confirmation for the exact operation and arguments; model-generated approval claims cannot grant it. Do not expose hidden expected actions or grader-only state to the agent, attacker or defense.
4. **Task-preserving responses:** our narrow Northwind renderer cannot support all exchanges, returns and booking workflows. Implement domain-appropriate verified outputs and interactive clarification; do not reuse Northwind's static policy as τ² policy.
5. **Budgets:** the current four-tool-attempt limit is too small for some legitimate episodes. Choose bounded episode budgets using training tasks, then freeze them. Retain per-write limits and exact-operation approvals.
6. **Scoring:** preserve the [upstream evaluator](https://github.com/sierra-research/tau2-bench/blob/033bf082f48e4a3c6a1256208e93cf2ce9c3bb6f/src/tau2/evaluator/evaluator.py) and its declared reward configuration. Add independent security oracles over tool events, exposed data and state changes. A task failing is not proof that an attack succeeded; a final database match can miss a transient data disclosure.
7. **Runtime:** use an isolated text-only environment. The inspected package requires Python >=3.12,<3.14, compatible with our tested 3.13. Its model layer uses LiteLLM, while ours directly calls Ollama. Local target/simulator compatibility and our 3B model's task competence must be measured. Some scoring modes can require further model calls; log simulator/judge configuration, token use, latency and errors. No paid requests were made during this review.

## Related security work to inspect first

[DUMA-Bench](https://arxiv.org/abs/2609.24662) explicitly extends τ²-bench for security. Its [repository](https://github.com/ai-security-lab-itmo/duma-benchmark) describes 35 scenarios across eight security domains, including identity spoofing, data oversharing and poisoned retrieval. This is an author's reported inventory, not our verified run. Inspect its tasks, scoring, dependencies and attacker regimes before choosing a pilot; its README alone does not establish compatibility or strong attack coverage.

[DoomArena](https://arxiv.org/abs/2504.14064) also provides a relevant example of attaching security evaluation to tool-agent environments, including τ-bench. It should be examined for reusable ideas; τ-bench integration does not automatically establish support for the current τ² revision. Building an adversarial layer around a task benchmark has prior work. Our contribution should be the controls and reproducible evidence, not a claim to invent that general approach.

## Recommendation

Start with retail because it most closely matches our existing ownership and write-approval controls. Use canonical τ² tasks for external task competence and security-utility measurements. Evaluate a suitable public security extension as well as carefully specified new attacks. Add telecom later to investigate user/agent coordination and attacks across those boundaries.

This would extend AgentSec Ops from one home-built test subject to an externally authored environment. A modified attacked subset must be labeled an extension/pilot, rather than an official full τ² score. Neither completing τ² tasks nor blocking a small attack sample establishes bulletproof protection.
