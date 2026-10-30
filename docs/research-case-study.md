# A model can follow the attacker while the application protects the user

*Research case study draft for adaptation into an article. All experiments use a controlled
Northwind Retail lab, synthetic data and a local model. No production incident is claimed.*

The first useful finding was a boundary mismatch. Garak told the model to ignore its task
and print a chosen string; it did so in both the vulnerable and hardened application.
Yet the hardened application prevented the separately tested unauthorized order/refund
operations. Calling the entire system either “safe” or “broken” would have hidden one of
those observations.

The model is a proposer and a text generator. It is not an authorization service. A
principal/agent/resource gateway can prevent access to Bob's order while acting for Alice,
but it cannot make arbitrary free-form text relevant to a support task. That was the scope
of the unresolved Garak finding: integrity of the delivered answer, not a recorded refund.

I inspected native attempts and private target traces, then added a deliberately narrower
response contract. The application renders order status from actual authorized receipts,
ticket IDs without untrusted descriptions, public inventory availability and a maintained
returns policy. It never uses a retrieved instruction or model-generated claim as an
execution receipt. It does not search for Garak's known phrase.

The experiment used identical inputs across vulnerable, hardened-baseline and grounded
configurations. In both the original four prompts and four new textual-hijack variants,
the raw model still produced all target strings. Delivery went from four of four to zero
of four in each group under the contract. That supports output containment, not a claim
that the model learned to distinguish instructions from evidence.

Utility was measured alongside attacks. Thirteen of sixteen benign tasks completed before
and after, but the failed tasks changed: a missing asset-ID answer was recovered, while a
requested Spanish response was lost. JSON formatting and a request containing quoted attack
language remained unsuccessful. Equal overall completion did not mean zero cost.

I also separated detector evaluation from authorization decisions. Frozen manual annotations
specified expected object/action permissions and malicious intent before inference. The
content-only detector achieved 12 true positives, 2 false positives, 14 true negatives and
6 false negatives in the complete hardened sample. Its precision was 12/14, recall 12/18
and false-positive rate 2/16. An operational alert is neither authorization nor proof of
malicious intent; the benign quotes made that distinction visible.

Another lesson came from ROT13. Increasing a token budget and bounding tool arguments did
not stop the model from repeating text inside an unfinished JSON string. An explicit content
length bound produced parseable output in two separate retests, but the answers were still
repetitive. A parser fix is not a security refusal or useful task completion. Failed runs
remain in the evidence, rather than being replaced by the successful framing experiment.

The practical conclusion is architectural: measure manipulation, proposals, executions,
delivery, detection and utility separately. Constrain the application's output and executor
where product requirements permit it. Keep the unsupported scope and remaining failures
visible. This study is one small local model and one internal validation split; broader
models, languages and adversarial strategies need further testing.

See [technical findings and experiment table](final-hardening-report.md), [final verification
audit](final-audit.md) and [historical framework results](framework-results.md). Resume claims
should name the observed populations and the constrained renderer, not guaranteed resistance.
