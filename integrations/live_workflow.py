"""Explicitly opt-in local live-framework workflow. No CI mocks or hosted GPU requirement."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess  # nosec B404
import sys
import time
import httpx

ROOT=Path(__file__).resolve().parents[1]


def validate_promptfoo_results(rows):
    """Expected assertion failures carry an 'error' string too; inspect actual provider output."""
    for row in rows:
        response=row.get('response') or {}
        if response.get('error') or response.get('output') is None:
            raise RuntimeError('Promptfoo provider execution failed')
        try:
            value=json.loads(response['output'])
            if 'outcome' not in value: raise ValueError('Missing original outcome oracle')
        except (ValueError,TypeError) as exc:
            raise RuntimeError('Promptfoo provider output is invalid') from exc
        components=(row.get('gradingResult') or {}).get('componentResults',[])
        if any('threw error' in c.get('reason','').lower() for c in components):
            raise RuntimeError('Promptfoo assertion configuration failed')


def run(output, pyrit_python, garak_python, node):
    output=Path(output).resolve()
    if output.exists() and any(output.iterdir()): raise FileExistsError('Use a new output directory')
    for executable in [pyrit_python,garak_python,node]:
        if not Path(executable).is_file(): raise FileNotFoundError(executable)
    entrypoint=ROOT/'integrations/promptfoo/node_modules/promptfoo/dist/src/entrypoint.js'
    if not entrypoint.exists(): raise FileNotFoundError('Install pinned Promptfoo with npm ci --prefix integrations/promptfoo')
    with httpx.Client(timeout=5,trust_env=False) as client:
        client.get('http://127.0.0.1:11434/api/tags').raise_for_status()
        for port in [8001,8002]:
            try:
                client.get(f'http://127.0.0.1:{port}/health')
            except httpx.ConnectError: continue
            raise RuntimeError(f'Port {port} already has a server. This workflow only manages its own processes.')
    output.mkdir(parents=True,exist_ok=True)
    audit=output/'target-audit';audit.mkdir()
    env=os.environ.copy()
    env['AGENTSEC_FRAMEWORK_AUDIT_DIR']=str(audit)
    env['AGENTSEC_PROMPTFOO_TRACE_PATH']=str(output/'promptfoo-traces.jsonl')
    env['PROMPTFOO_PYTHON']=sys.executable;env['PROMPTFOO_DISABLE_TELEMETRY']='1'
    env['PATH']=str(Path(node).parent)+os.pathsep+env.get('PATH','')
    processes=[];streams=[];ledger=[]
    def execute(command,name,allowed_codes=(0,)):
        start=time.time()
        with (output/(name+'.log')).open('w') as stream:
            # Fixed local modules/CLI; explicit argument list; no shell.
            result=subprocess.run(command,cwd=ROOT,env=env,stdout=stream,stderr=subprocess.STDOUT,timeout=1800,check=False)  # nosec B603
        ledger.append({'name':name,'command':command,'exit_code':result.returncode,'seconds':time.time()-start})
        (output/'commands.json').write_text(json.dumps(ledger,indent=2))
        if result.returncode not in allowed_codes: raise RuntimeError(f'{name} failed: see {output/(name+".log")}')
    try:
        for mode,port in [('vulnerable',8001),('hardened',8002)]:
            local_env={**env,'AGENTSEC_MODE':mode,'AGENTSEC_RESPONSE_POLICY':'model' if mode=='vulnerable' else 'grounded',
                       'AGENTSEC_AUDIT_PATH':str(audit/f'target-{mode}.jsonl'),'AGENTSEC_NUM_PREDICT':'768'}
            stream=(output/f'{mode}-server.log').open('w');streams.append(stream)
            command=[sys.executable,'-m','uvicorn','app.main:app','--host','127.0.0.1','--port',str(port)]
            # Fixed loopback server with explicit environment; no shell.
            proc=subprocess.Popen(command,cwd=ROOT,env=local_env,stdout=stream,stderr=subprocess.STDOUT)  # nosec B603
            processes.append(proc)
        for _ in range(100):
            if any(p.poll() is not None for p in processes): raise RuntimeError('A target process exited; inspect server logs')
            try:
                with httpx.Client(timeout=1,trust_env=False) as client:
                    states=[client.get(f'http://127.0.0.1:{p}/health').json() for p in [8001,8002]]
                if [s['mode'] for s in states]==['vulnerable','hardened']:
                    (output/'target-health.json').write_text(json.dumps(states,indent=2));break
            except (httpx.HTTPError,ValueError): pass
            time.sleep(.1)
        else: raise RuntimeError('Target startup timed out')
        config=json.loads((ROOT/'integrations/promptfoo/promptfooconfig.json').read_text())
        for provider in config['providers']:
            provider['id']='file://'+str(ROOT/'integrations/promptfoo/provider.py')
            provider['config']['response_policy']='grounded' if provider['config']['mode']=='hardened' else 'model'
        config_path=output/'promptfoo.config.json';config_path.write_text(json.dumps(config,indent=2))
        execute([node,str(entrypoint),'eval','-c',str(config_path),'--no-cache','--max-concurrency','1','-o',str(output/'promptfoo.json')], 'promptfoo',allowed_codes=(0,100))
        # Promptfoo exits 100 for failing security assertions in the deliberately vulnerable baseline.
        pf=json.loads((output/'promptfoo.json').read_text())['results']['results']
        validate_promptfoo_results(pf)
        execute([pyrit_python,str(ROOT/'integrations/pyrit/experiment.py'),'--output',str(output/'pyrit')],'pyrit')
        execute([garak_python,str(ROOT/'integrations/garak/run.py'),'--output',str(output/'garak'),'--cap','4'],'garak')
        summary={'real_model':True,'targets':states,'promptfoo':{'total':len(pf),'passed':sum(r['success'] for r in pf)},
                 'pyrit':'pyrit/report.json','garak':'garak/report.json','commands':ledger}
        (output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
        print(json.dumps(summary,indent=2))
    finally:
        for proc in processes:
            if proc.poll() is None: proc.terminate()
        for proc in processes:
            try: proc.wait(timeout=15)
            except subprocess.TimeoutExpired: proc.kill();proc.wait()
        for stream in streams: stream.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',required=True)
    parser.add_argument('--pyrit-python',required=True)
    parser.add_argument('--garak-python',required=True)
    parser.add_argument('--node',default=shutil.which('node'))
    args=parser.parse_args()
    run(args.output,args.pyrit_python,args.garak_python,args.node)
