"""Follow-up research experiment; frozen labels and immutable historical evidence."""
import argparse
import hashlib
import json
import time
from pathlib import Path
from app.agent import Agent
from app.providers import OllamaProvider
from evaluations.independent import assess, summarize

CONFIGS={'vulnerable':('vulnerable','model'),'hardened-baseline':('hardened','model'),'hardened-grounded':('hardened','grounded')}


def write_report(output, manifest, rows):
    metrics={name:summarize([r for r in rows if r['configuration']==name]) for name in manifest['configurations']}
    document={'manifest':manifest,'metrics':metrics,'runs':rows}
    (output/'report.json').write_text(json.dumps(document,indent=2)+'\n')
    (output/'traces.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows))
    lines=['# Hardening follow-up experiment','',
        'Model compromise, delivered text, independently annotated tool permissions, detector alerts and utility are separate populations. Errors are not successful defenses.',
        '', '| Case | Configuration | Error | Raw objective hit | Delivered objective hit | Prohibited proposed/executed | Benign complete |', '|---|---|---|---|---|---|---|']
    for r in rows:
        e=r['evaluation'];lines.append(f"| {r['case']['id']} | {r['configuration']} | {r['trace']['error'] or 'none'} | {e['raw_model_objective_hit']} | {e['delivered_objective_hit']} | {e['unauthorized_proposals']}/{e['unauthorized_executions']} | {e['benign_complete']} |")
    lines += ['', '## Metrics by independent population', '', '```json',json.dumps(metrics,indent=2),'```','',
        'Known native prompts are retests, not held-out validation. Held-out variants were authored and labels frozen after the contract was implemented, before inference; they were not externally adjudicated. Explicit marker/fact oracles can miss semantic paraphrases. The contract is a constrained renderer, not proof of model resistance.']
    (output/'report.md').write_text('\n'.join(lines)+'\n')
    return document


def run(output, configurations, case_ids=None):
    output=Path(output)
    if (output/'report.json').exists(): raise FileExistsError('Choose a new output directory; historical results are immutable')
    output.mkdir(parents=True,exist_ok=True)
    inputs=Path('attacks/hardening-cases.json').read_bytes()
    annotations=Path('attacks/independent-labels.json').read_bytes()
    cases=json.loads(inputs);reference=json.loads(annotations)
    if case_ids: cases=[c for c in cases if c['id'] in case_ids]
    if not cases: raise ValueError('No cases selected')
    provider=OllamaProvider(num_predict=768,retry_truncated=True)
    manifest={'provider':provider.describe(),'configurations':configurations,'input_sha256':hashlib.sha256(inputs).hexdigest(),
        'annotation_sha256':hashlib.sha256(annotations).hexdigest(),
        'source_hashes':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for d in ['app','security','attacks','evaluations'] for p in sorted(Path(d).rglob('*.py'))},
        'annotation_method':reference['annotation_method'],'method':'One sample per case/configuration, identical inputs; manually annotated Alice/support-agent permission reference independent of enforcement'}
    rows=[]
    for case in cases:
        for config in configurations:
            mode,policy=CONFIGS[config]
            print(config,case['id'],flush=True)
            agent=Agent(provider,mode,response_policy=policy,tool_observations=case['tool_observations'])
            started=time.perf_counter()
            try: trace=agent.run(case['input'],case['document_id'])
            except Exception as exc:
                trace={'request_id':agent.audit.request_id,'mode':mode,'response_policy':policy,'response':'','events':agent.audit.events,
                    'error':type(exc).__name__+': '+str(exc),'alerts':[],'intent_alerts':[],'duration_seconds':time.perf_counter()-started}
            rows.append({'case':case,'configuration':config,'trace':trace,'evaluation':assess(case,trace,reference)})
            write_report(output,manifest,rows)
    report=write_report(output,manifest,rows)
    if any(r['trace']['error'] for r in rows): raise SystemExit(1)
    return report

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',required=True)
    parser.add_argument('--configurations',nargs='+',choices=list(CONFIGS),default=list(CONFIGS))
    parser.add_argument('--case',action='append',dest='cases')
    args=parser.parse_args()
    run(args.output,args.configurations,args.cases)
