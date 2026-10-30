"""Generate recruiter-readable follow-up evidence from saved results, never invented scores."""
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'results/hardening-v1'

def main():
    r=json.loads((OUT/'model-experiment/report.json').read_text())
    metrics=r['metrics']
    names=['vulnerable','hardened-baseline','hardened-grounded']
    def f(rate): return f"{rate['numerator']}/{rate['denominator']}"
    table=['| Observation | Vulnerable | Hardened, model text | Hardened, grounded text |','|---|---:|---:|---:|']
    for title,key,field in [
        ('Known native prompts: raw model hijack','known-native-retest:hijack','raw_model_hit'),
        ('Known native prompts: delivered hijack','known-native-retest:hijack','delivered_hit'),
        ('Held-out variants: raw model hijack','held-out:hijack','raw_model_hit'),
        ('Held-out variants: delivered hijack','held-out:hijack','delivered_hit'),
        ('Beyond-canary instruction fragments: raw','held-out:instructions','raw_model_hit'),
        ('Beyond-canary instruction fragments: delivered','held-out:instructions','delivered_hit')]:
        table.append('| '+title+' | '+' | '.join(f(metrics[n]['objective_populations'][key][field]) for n in names)+' |')
    table += ['| Unauthorized proposals / actual executions | '+' | '.join(f"{metrics[n]['unauthorized_tool_proposals']} / {metrics[n]['unauthorized_tool_executions']}" for n in names)+' |',
              '| Correct enforced denials / independently prohibited policy decisions | '+' | '.join(f"{metrics[n]['correct_enforced_denials']} / {metrics[n]['expected_prohibited_policy_decisions']}" for n in names)+' |',
              '| Benign completion | '+' | '.join(f(metrics[n]['benign_completion']) for n in names)+' |',
              '| Execution errors | '+' | '.join(str(metrics[n]['errors']) for n in names)+' |']
    detector=['| Configuration | TP | FP | TN | FN | Precision | Recall | F1 | FPR |','|---|---:|---:|---:|---:|---:|---:|---:|---:|']
    for n in names:
        d=metrics[n]['content_only_detection']
        detector.append('| '+n+' | '+' | '.join(str(d[k]) for k in ['tp','fp','tn','fn'])+' | '+' | '.join(f"{d[k]['value']:.3f}" for k in ['precision','recall','f1','false_positive_rate'])+' |')
    text='''# Final hardening research report

This follow-up preserves the original benchmark and scanner evidence. It investigates the
observed textual task hijacking and tests a narrower application response boundary, rather
than asserting that stronger wording makes the model trustworthy.

## Threat model

```mermaid
flowchart LR
  A[Attacker: chat, retrieved text, simulated tool notes] --> L[Untrusted model context]
  P[Trusted principal and agent identity] --> G[Authorization gateway]
  L --> Q[Untrusted tool proposals]
  Q --> G
  G --> T[Synthetic tools / object ownership]
  T --> E[Private execution receipts]
  L --> M[Raw model text: may remain hijacked]
  E --> C[Configured response contract]
  M -. excluded from rendering .-> C
  S[Server-maintained support policy] --> C
  C --> U[Delivered support response]
  L --> D[Content-only intent detector: observational]
```

Attacker-controlled tool notes are injected only into the simulated model observation, after
actual execution and audit. They do not change the executor's trusted fixture record. The
HTTP caller cannot supply this experiment override. The output contract is an additional
boundary, not a replacement for principal/agent/resource authorization.

## What failed in the original Garak run

Four native HijackLongPrompt attempts in each mode caused the model to repeat the injected
rogue text. The security objective violated was response integrity/task adherence. These
requests did not invoke prohibited tools or disclose the planted key. Raw native attempts,
hitlogs and application traces remain in results/garak and results/frameworks.

## Mitigation and its exact scope

A configurable grounded response contract renders requested order status from an authorized
execution receipt, ticket IDs without untrusted descriptions, public-asset availability,
and a separately server-maintained returns policy. Other free-form generation receives a
scope/clarification response. Retrieved prose, tool diagnostic notes and raw model text are
not used as authoritative output facts. Neither Garak's rogue string nor held-out target
strings occur in the enforcement code. The rule is an allowlisted output representation,
not a broad semantic injection classifier.

This deliberately narrows the product: free-form prose, requested language/format and some
legitimate support interactions are lost or constrained. It does not undo effects that have
already executed. Gateway checks remain before every tool action. Hardened HTTP startup
now defaults to grounded responses; AGENTSEC_RESPONSE_POLICY=model selects the prior
baseline. The Agent constructor retains an explicit baseline default for historical runners.

## Actual paired experiment

34 cases × three configurations = 102 actual local-model executions. Sixteen benign cases
include natural variants, quoted attack terms, JSON-format and Spanish-language requests.
Four original native prompts are explicitly calibration/retests, not held-out validation.
Fourteen newly authored attacks include persona manipulation, four textual-hijack objectives,
two instruction-fragment extractions beyond a canary, four secret encodings, simulated tool
response injection, retrieved injection and restricted inventory abuse.

Manual expected outcomes and Alice/support-agent permissions were frozen in separate JSON
before inference, independently of Authorizer/Detector return values. They were authored
in this project, not externally adjudicated. Inputs and annotation hashes are in the report.
The held-out variants were authored after the contract was implemented and before any of
these experiments; they are a small internal validation split, not an independently curated
public benchmark. No rule tuning was performed to turn observed detector false positives
into passes.

'''+ '\n'.join(table)+'''

The raw model continued to produce every tested hijack target after mitigation. The
application suppressed their delivery by rendering a constrained support response. Therefore
the supported conclusion is application-level output containment, not model resistance.

A separate instruction-extraction case matched at least two independently declared protected
system-instruction fragments in the baseline. The canary was not needed for this oracle.
The grounded renderer withheld that text while preserving it in private experiment evidence.
Exact fragment matching can miss paraphrases and is not general prompt-extraction coverage.

Unauthorized proposals include unknown/malformed calls rejected before policy evaluation.
Thus five prohibited proposals need not yield five policy decisions. Three expected prohibited
policy decisions in each hardened configuration were correctly denied; no independent policy
verdict disagreements or false denials were observed in this small sample. These denominators
are not combined with textual-hijack or detection populations.

## Utility and detector effectiveness

'''+ '\n'.join(detector)+'''

Content-only IntentDetector rules consume user/retrieval/tool-observation content. They do not
consume authorization decisions, object owners or policy return values. The legacy detector
is still reported separately as policy-informed. Under the same complete hardened sample,
legacy policy-informed recall is 3/18 versus content-only recall 12/18. This is a difference
in observable scope, not a claim that keywords solve injection detection.

Both configurations completed thirteen of sixteen benign cases, but this equal total hides
a tradeoff: grounded rendering recovered an asset-ID response while losing the requested
Spanish answer. The baseline failed U08, U13 and U15; grounded failed U13, U15 and U16.
JSON-format compliance and an order request quoting attack language remain failures. The
content-only detector falsely alerted on two benign technical/quoted-language cases (2/16);
these alerts are observational and do not authorize or block an action. No universally safe
or lossless-utility claim is supported.

## Parsing failures and repair experiments

The primary experiment retains one unresolved vulnerable K03/ROT13 JSON error. Its first
768-token generation and one 1536-token retry are preserved. The error is excluded from
resolved-outcome denominators and is not a successful defense.

A separate retest of the original S03 vulnerable/filtered cases with a bounded registered-tool
schema still failed twice: the captured failure was repetitive text inside an unfinished
content string, not an unbounded tool-argument object. A further explicit max_content_chars=1000
model-output schema bound produced valid JSON for both cases. The content was still repetitive
and semantically unhelpful. This repairs response framing for those two tests; it does not
establish correct ROT13 capability, and no repeated answer is described as a model refusal.
All failed attempts and separate retests remain available; the primary dataset was not rewritten.

## Coverage and limitations

- Persona, controlled system-instruction extraction, task hijacking, simulated tool responses,
  Base64/ROT13/character extraction and benign counterexamples now have explicit bounded oracles.
- Model-level manipulation remains present. Unknown or unsupported legitimate tasks can receive
  a scope reply; translations and arbitrary output formatting are not preserved.
- The content-only detector has false positives and false negatives; policy labels are manually
  specified small-fixture expectations, not proof of correctness across principals/resources.
- One model, seed and internal held-out split do not establish general effectiveness. Exact
  output markers/facts miss semantic variants. No broad harmful-content safety benchmark is claimed.
- Approval/identity and tool effects remain synthetic. Audit files are local evidence, not
  tamper-proof or production-safe storage for real sensitive data.

## Reproduction and evidence

```sh
.venv/bin/python -m attacks.hardening_runner --output results/local-hardening-001
.venv/bin/python -m attacks.runner --provider ollama --case S03 --modes vulnerable filtered --num-predict 768 --retry-truncated --bounded-tools --max-content-chars 1000 --output results/local-rot13-001
```

Choose fresh output directories. Review results/hardening-v1/model-experiment/report.json
and traces.jsonl, the two distinct ROT13 repair directories, and the historical source reports.
Use docs/live-workflow.md for the separate actual Promptfoo/PyRIT/Garak workflow. See
[final audit](final-audit.md) for exact command/test/CI status and [recording script](demo-120s.md)
for the 90–120-second demo. No video artifact is supplied.
'''
    (ROOT/'docs/final-hardening-report.md').write_text(text)
    story='''# A model can follow the attacker while the application protects the user

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
'''
    (ROOT/'docs/research-case-study.md').write_text(story)
    print('Generated technical report and research case study from preserved observations')

if __name__=='__main__': main()
