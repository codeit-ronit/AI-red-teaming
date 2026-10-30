"""Capture actual lab execution for an edited terminal-replay demonstration."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess  # nosec B404
import sys
import time
from datetime import datetime
from zoneinfo import ZoneInfo

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from app.agent import Agent
from app.providers import OllamaProvider
from evaluations.independent import assess


def main(output):
    out=Path(output);out.mkdir(exist_ok=True,parents=True)
    if (out/'capture.json').exists(): raise FileExistsError('Use a new capture directory')
    started=time.monotonic();events=[]
    def record(section,data):
        event={'elapsed_seconds':round(time.monotonic()-started,3),'section':section,'data':data}
        events.append(event)
        with (out/'events.jsonl').open('a') as stream:stream.write(json.dumps(event)+'\n')
        print('\n'+section.upper(),flush=True)
        print(json.dumps(data,indent=2),flush=True)
    provider=OllamaProvider(num_predict=768,retry_truncated=True,bounded_tools=True,max_content_chars=1000)
    model=provider.describe()
    # Read-only fixed Git command; no shell or model-controlled arguments.
    commit=subprocess.check_output([shutil.which('git'),'rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    record('capture',{'recorded_at':datetime.now(ZoneInfo('Asia/Kolkata')).isoformat(),'source_commit':commit,
                      'model':model['model'],'provider':'actual local Ollama; no scripted model fixture'})
    cases=json.loads((ROOT/'attacks/hardening-cases.json').read_text())
    reference=json.loads((ROOT/'attacks/independent-labels.json').read_text())
    selections=[('authorized','U01','hardened','grounded'),('text_before','H03','hardened','model'),
                ('text_after','H03','hardened','grounded'),('tool_before','D04','vulnerable','model'),
                ('tool_after','D04','hardened','grounded')]
    rows=[]
    for section,case_id,mode,policy in selections:
        case=next(c for c in cases if c['id']==case_id)
        trace=Agent(provider,mode,response_policy=policy,tool_observations=case['tool_observations']).run(case['input'],case['document_id'])
        evaluation=assess(case,trace,reference)
        row={'section':section,'case':case,'trace':trace,'evaluation':evaluation}
        rows.append(row)
        raw=[e['content'] for e in trace['events'] if e['kind']=='model_output' and e['content']]
        proposals=[c for e in trace['events'] if e['kind']=='model_output' for c in e['proposed_tool_calls']]
        decisions=[{'tool':e['decision']['tool'],'allowed':e['decision']['allowed'],'policy':e['decision']['policy_id'],
                    'enforced':e['enforced']} for e in trace['events'] if e['kind']=='authorization']
        record(section,{'case':case_id,'mode':mode,'response_policy':policy,'request':case['input'],
                        'raw_model_answers':raw,'proposed_calls':proposals,'authorization':decisions,
                        'actual_tool_executions':sum(e['kind']=='tool_execution' for e in trace['events']),
                        'unauthorized_executions':evaluation['unauthorized_executions'],
                        'raw_attack_target_seen':evaluation['raw_model_objective_hit'],
                        'delivered_attack_target_seen':evaluation['delivered_objective_hit'],
                        'delivered_response':trace['response'],'error':trace['error']})
        (out/'model-traces.json').write_text(json.dumps({'metadata':model,'runs':rows},indent=2))
    command=[sys.executable,'-m','pytest','-m','not model','-q',f'--junitxml={out}/pytest.xml']
    result=subprocess.run(command,cwd=ROOT,text=True,capture_output=True,check=False)  # nosec B603
    (out/'pytest.log').write_text(result.stdout+result.stderr)
    record('tests',{'command':command,'exit_code':result.returncode,'output_tail':result.stdout.splitlines()[-4:]})
    ci_command=[shutil.which('gh'),'run','list','--repo','codeit-ronit/AI-red-teaming','--workflow','security.yml','--limit','1',
                '--json','databaseId,status,conclusion,headSha,url']
    ci=subprocess.run(ci_command,cwd=ROOT,text=True,capture_output=True,check=False)  # nosec B603
    ci_data=json.loads(ci.stdout) if ci.returncode==0 else {'status':'unavailable','error':ci.stderr.strip()}
    record('hosted_ci_snapshot',ci_data)
    manifest={'capture_type':'Actual execution transcript, edited terminal replay; not a desktop screen capture',
        'timestamp':datetime.now(ZoneInfo('Asia/Kolkata')).isoformat(),'source_commit':commit,
        'actual_model_executions':len(rows),'scripted_model_provider_used':False,
        'source_hashes':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for d in ['app','security'] for p in (ROOT/d).glob('*.py')},
        'selection_note':'Five illustrative executions selected from existing cases; not a new benchmark or statistical sample',
        'events':events,'ci_snapshot':ci_data}
    (out/'capture.json').write_text(json.dumps(manifest,indent=2)+'\n')
    if result.returncode or any(r['trace']['error'] for r in rows):raise SystemExit(1)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True)
    main(parser.parse_args().output)
