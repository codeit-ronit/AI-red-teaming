"""Render captured execution evidence as a narrated, captioned terminal replay.

Media-only dependencies: Pillow and an FFmpeg executable. The renderer does not execute
models or invent result values. macOS `say` provides explicitly synthetic offline narration.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import shutil
import subprocess  # nosec B404
import textwrap
from PIL import Image, ImageDraw, ImageFont, __version__ as pillow_version

ROOT=Path(__file__).resolve().parents[1]
W,H=1600,900
BG='#09111f';PANEL='#111d30';BORDER='#253650';WHITE='#e7eefb';MUTED='#98acc8';GREEN='#57e6ad';RED='#ff818e';CYAN='#69d2ff';GOLD='#f7cf80'
FONT='/System/Library/Fonts/Menlo.ttc'
UI='/System/Library/Fonts/Supplemental/Arial.ttf'

def font(n,mono=False):return ImageFont.truetype(FONT if mono else UI,n)

def tool(command,**kwargs):
    # All executables/arguments are explicit media utilities; no shell evaluation.
    return subprocess.run(command,check=True,**kwargs)  # nosec B603


def require(condition,message):
    if not condition: raise ValueError(message)


def render(capture,output,ffmpeg):
    capture=Path(capture).resolve();output=Path(output).resolve()
    if output.exists():raise FileExistsError('Preserve existing videos; choose a new filename')
    output.parent.mkdir(parents=True,exist_ok=True)
    evidence=json.loads((capture/'capture.json').read_text())
    entries={e['section']:e['data'] for e in evidence['events']}
    a,b,c,v,h=[entries[n] for n in ['authorized','text_before','text_after','tool_before','tool_after']]
    require(all(x['error'] is None for x in [a,b,c,v,h]), 'Capture contains an execution error')
    require(b['delivered_attack_target_seen'] and c['raw_attack_target_seen'] and not c['delivered_attack_target_seen'], 'Capture does not support the advertised before/after demonstration')
    require(v['unauthorized_executions']>0 and h['unauthorized_executions']==0, 'Capture does not demonstrate the claimed execution boundary')
    require(bool(h['proposed_calls']), 'No hardened tool proposal was observed')
    ci=evidence['ci_snapshot'][0];require(ci['conclusion']=='success','CI snapshot did not pass')
    tests=entries['tests'];require(tests['exit_code']==0,'Captured tests failed')
    passed=next(line.strip() for line in tests['output_tail'] if re.search(r'\d+ passed',line))
    study=json.loads((ROOT/'results/hardening-v1/model-experiment/report.json').read_text())['metrics']['hardened-grounded']
    utility=study['benign_completion'];fp=study['content_only_detection']['false_positive_rate']
    def lines(*items):return list(items)
    scenes=[
      {'title':'A model can follow an attacker.', 'subtitle':'The application can still enforce the boundary.',
       'label':'01  /  SECURITY QUESTION','badge':'ACTUAL EXECUTION',
       'body':lines(('$ .venv/bin/python scripts/capture_demo.py --output results/demo-v1',CYAN),('',WHITE),
           ('TARGET   Northwind Retail / synthetic support data',WHITE),('MODEL    Ollama / qwen2.5-coder:3b / local Apple M2',WHITE),
           ('SCOPE    Five selected executions; not a new benchmark',MUTED),('',WHITE),
           ('Attacker input -> Model proposal -> Authorization gateway',CYAN),('                                    |',MUTED),
           ('                         authorized tool receipts',GREEN),('                                    |',MUTED),
           ('                           Response contract -> User',GREEN)),
       'caption':'Measure model behavior, tool execution and delivered text separately.',
       'speech':'AgentSec Ops is a local AI security laboratory built around a retail support agent. This edited terminal replay uses fresh local model responses, synthetic data, and recorded execution evidence. The model proposes actions. Independent application controls decide what executes and what reaches the user.'},
      {'title':'First, a legitimate request.', 'subtitle':'Alice checks her own order.', 'label':'02  /  AUTHORIZED TASK','badge':'ALLOWED',
       'body':lines(('request = '+json.dumps(a['request']),CYAN),('',WHITE),('principal: alice    agent: support-agent',WHITE),
           ('proposed tool: '+json.dumps(a['proposed_calls'][0]),WHITE),('',WHITE),
           ('authorization.allowed: '+str(a['authorization'][0]['allowed']).lower(),GREEN),
           ('actual tool executions: '+str(a['actual_tool_executions']),GREEN),('',WHITE),
           ('delivered response:',MUTED),(a['delivered_response'],GREEN)),
       'caption':'Useful support requires a real authorized result, not a model claim.',
       'speech':'Alice asks about her own order. The model proposes an order lookup, the gateway authorizes it, and the tool executes. The response contract renders the status from that actual receipt. The result is a working, authorized support task.'},
      {'title':'Then, an injected instruction.', 'subtitle':'The existing tool gateway alone does not contain arbitrary text.', 'label':'03  /  BEFORE: MODEL TEXT','badge':'HIJACK DELIVERED',
       'body':lines(('request:',CYAN),(b['request'],WHITE),('',WHITE),
           ('configuration: hardened authorization + model text',MUTED),('',WHITE),
           ('raw model answer:',MUTED),(b['raw_model_answers'][-1],RED),('',WHITE),
           ('delivered response:',MUTED),(b['delivered_response'],RED),('',WHITE),
           ('attacker target delivered: '+str(b['delivered_attack_target_seen']).lower(),RED)),
       'caption':'Textual hijacking is an integrity failure, even without a prohibited tool call.',
       'speech':'The next request mixes a valid order task with an instruction to append an attacker selected phrase. With model text delivered directly, the phrase reaches the user. Authorization is active, but it does not make arbitrary model output relevant or trustworthy.'},
      {'title':'Same input. Controlled delivery.', 'subtitle':'The raw model remains manipulated; the application renders approved facts.', 'label':'04  /  AFTER: RESPONSE CONTRACT','badge':'DELIVERY CONTAINED',
       'body':lines(('identical request:',CYAN),(c['request'],WHITE),('',WHITE),
           ('raw model answer:',MUTED),(c['raw_model_answers'][-1],RED),('',WHITE),
           ('raw attacker target present: '+str(c['raw_attack_target_seen']).lower(),RED),
           ('delivered attacker target: '+str(c['delivered_attack_target_seen']).lower(),GREEN),('',WHITE),
           ('delivered response:',MUTED),(c['delivered_response'],GREEN)),
       'caption':'No known attack-string filter: render supported facts from authorized receipts.',
       'speech':'The same input now uses the grounded response contract. The raw model still includes the attacker phrase. The application instead renders supported facts from authorized tool receipts, keeping that phrase out of the delivered response. This demonstrates output containment, not a model that resists injection.'},
      {'title':'Tool safety is a separate boundary.', 'subtitle':'A restricted inventory request must be denied before execution.', 'label':'05  /  EXECUTION AUTHORIZATION','badge':'DENIED BEFORE EXECUTION',
       'body':lines(('proposed call: '+json.dumps(h['proposed_calls'][0]),CYAN),('',WHITE),
           ('VULNERABLE',RED),('shadow policy allowed: '+str(v['authorization'][0]['allowed']).lower()+'    enforced: '+str(v['authorization'][0]['enforced']).lower(),MUTED),
           ('unauthorized executions: '+str(v['unauthorized_executions']),RED),('',WHITE),
           ('HARDENED',GREEN),('policy: '+h['authorization'][0]['policy']+'    enforced: '+str(h['authorization'][0]['enforced']).lower(),WHITE),
           ('unauthorized executions: '+str(h['unauthorized_executions']),GREEN),('',WHITE),
           ('delivered response:',MUTED),(h['delivered_response'],GREEN)),
       'caption':'Inspect actual tool-execution events. A refusal-looking answer is not proof of safety.',
       'speech':'Now the model requests a restricted inventory record. The vulnerable gateway executes it despite a shadow policy denial. The hardened gateway enforces the denial before execution. We inspect actual tool events, rather than trusting the model to say whether an operation happened.'},
      {'title':'Verified, with honest limits.', 'subtitle':'Reproducible code, native scanner evidence and a passing hosted pipeline.', 'label':'06  /  ENGINEERING EVIDENCE','badge':'VERIFIED',
       'body':lines(("$ .venv/bin/python -m pytest -m 'not model' -q",CYAN),(passed,GREEN),('',WHITE),
           ('HOSTED CI SNAPSHOT',MUTED),('status: '+ci['status']+'    conclusion: '+ci['conclusion'],GREEN),
           ('run: '+str(ci['databaseId']),WHITE),('',WHITE),
           ('FULL STUDY (separate from this five-run demonstration)',MUTED),
           (f"benign completion: {utility['numerator']}/{utility['denominator']}    benign detector false alerts: {fp['numerator']}/{fp['denominator']}",GOLD),
           ('raw model hijacking, utility failures and detection limits remain',GOLD),('',WHITE),
           ('github.com/codeit-ronit/AI-red-teaming',CYAN)),
       'caption':'Selected cases illustrate boundaries; the research report contains failures and limitations.',
       'speech':'The regression tests pass, and the captured hosted security workflow also passed. The full research report includes actual Promptfoo, PyRIT and Garak runs, utility failures, and false alerts. This demonstration illustrates selected boundaries. It does not claim complete security or general model resistance.'}
    ]
    work=capture/'media-build';work.mkdir(exist_ok=True)
    say=shutil.which('say')
    durations=[]
    for i,scene in enumerate(scenes):
        txt=work/f'narration-{i}.txt';txt.write_text(scene['speech'])
        voice=work/f'voice-{i}.aiff'
        tool([say,'-v','Samantha','-r','155','-f',str(txt),'-o',str(voice)])
        meta=tool([ffmpeg,'-hide_banner','-i',str(voice),'-f','null','-'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
        match=re.search(r'Duration: (\d+):(\d+):(\d+\.\d+)',meta.stderr)
        seconds=int(match[1])*3600+int(match[2])*60+float(match[3])
        duration=max(12,math.ceil(seconds+2.5));durations.append(duration)
        tool([ffmpeg,'-y','-loglevel','error','-i',str(voice),'-af','adelay=400,apad','-t',str(duration),'-ar','48000','-ac','1',str(work/f'voice-{i}.wav')])
    def make_frame(scene,index,reveal):
        im=Image.new('RGB',(W,H),BG);d=ImageDraw.Draw(im)
        d.text((65,25),'AGENTSEC OPS',font=font(21,True),fill=CYAN)
        d.text((1015,28),'ACTUAL LOCAL EXECUTION / EDITED REPLAY',font=font(17,True),fill=MUTED)
        d.text((65,67),scene['title'],font=font(39),fill=WHITE)
        d.text((67,118),scene['subtitle'],font=font(23),fill=MUTED)
        d.rounded_rectangle((60,167,1540,732),radius=16,fill=PANEL,outline=BORDER,width=2)
        for x,col in [(88,'#f07178'),(111,'#efc06c'),(134,'#69c18c')]:d.ellipse((x,185,x+12,197),fill=col)
        d.text((164,182),'northwind-lab  /  '+scene['label'],font=font(17,True),fill=MUTED)
        color=RED if scene['badge']=='HIJACK DELIVERED' else GREEN
        d.text((1035,182),scene['badge'],font=font(17,True),fill=color)
        y=225;body=[]
        for text,col in scene['body']:
            wrapped=textwrap.wrap(text,width=103,replace_whitespace=False,drop_whitespace=True) or ['']
            body.extend((line,col) for line in wrapped)
        require(len(body)<=17, f'Scene {index} text would overflow: {len(body)} lines')
        if reveal:body=body[:3]
        for text,col in body:
            d.text((86,y),text,font=font(22,True),fill=col);y+=28
        d.rounded_rectangle((60,755,1540,838),radius=12,fill='#14263a')
        for n,line in enumerate(textwrap.wrap(scene['caption'],width=109)):
            d.text((83,775+n*28),line,font=font(24),fill=WHITE)
        d.text((65,858),'SOURCE '+evidence['source_commit'][:7]+'  |  SYNTHETIC DATA  |  OFFLINE SYNTHETIC NARRATION',font=font(16,True),fill=MUTED)
        d.text((1335,858),f'{index+1} / {len(scenes)}',font=font(17,True),fill=CYAN)
        for n in range(len(scenes)):
            x=1140+n*29;d.rectangle((x,863,x+20,869),fill=CYAN if n<=index else BORDER)
        return im
    frame_lines=['ffconcat version 1.0'];audio_lines=['ffconcat version 1.0'];subtitles=[];offset=0
    def stamp(seconds):
        ms=int(seconds*1000);return f'{ms//3600000:02}:{ms//60000%60:02}:{ms//1000%60:02},{ms%1000:03}'
    for i,(scene,duration) in enumerate(zip(scenes,durations)):
        for reveal,hold,suffix in [(True,2,'command'),(False,duration-2,'result')]:
            frame=work/f'scene-{i}-{suffix}.png';make_frame(scene,i,reveal).save(frame)
            frame_lines += [f"file '{frame.resolve()}'",f'duration {hold}']
        audio_lines.append(f"file '{(work/f'voice-{i}.wav').resolve()}'")
        subtitles += [str(i+1),stamp(offset)+' --> '+stamp(offset+duration),scene['caption'],''];offset+=duration
    frame_lines.append(f"file '{frame.resolve()}'")
    frames=work/'frames.ffconcat';frames.write_text('\n'.join(frame_lines))
    voices=work/'audio.ffconcat';voices.write_text('\n'.join(audio_lines))
    output.with_suffix('.srt').write_text('\n'.join(subtitles))
    tool([ffmpeg,'-y','-loglevel','error','-f','concat','-safe','0','-i',str(frames),'-f','concat','-safe','0','-i',str(voices),
          '-vf','fps=15,format=yuv420p','-c:v','libx264','-preset','medium','-crf','20','-c:a','aac','-b:a','96k',
          '-t',str(offset),'-movflags','+faststart',str(output)])
    make_frame(scenes[0],0,False).save(output.parent/'demo-preview.png')
    narration='\n\n'.join(f"{i+1}. {s['title']}\n{s['speech']}" for i,s in enumerate(scenes))
    (output.parent/'demo-narration.txt').write_text(narration+'\n')
    manifest={'video':str(output.relative_to(ROOT)),'duration_seconds':offset,'resolution':[W,H],'fps':15,'pillow_version':pillow_version,
              'capture_manifest_sha256':hashlib.sha256((capture/'capture.json').read_bytes()).hexdigest(),
              'video_sha256':hashlib.sha256(output.read_bytes()).hexdigest(),'source_commit':evidence['source_commit'],
              'format':'Edited terminal replay from actual captured execution, not desktop screen capture',
              'narration':'Offline macOS Samantha synthetic voice; not the developer speaking',
              'scene_seconds':durations,'raw_evidence':str(capture.relative_to(ROOT))}
    (output.parent/'demo-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(manifest,indent=2))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--capture',required=True);parser.add_argument('--output',required=True);parser.add_argument('--ffmpeg',required=True)
    args=parser.parse_args();render(args.capture,args.output,args.ffmpeg)
