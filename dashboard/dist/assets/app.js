'use strict';
const REPO = 'https://github.com/codeit-ronit/AI-red-teaming/blob/main/';
const CONFIG_NAMES = {'vulnerable':'Vulnerable','hardened-baseline':'Hardened · model text','hardened-grounded':'Hardened · grounded text'};
const state = {data:null,selected:'H03',configuration:'hardened-grounded'};
const $ = (selector) => document.querySelector(selector);
const escapeHTML = (value) => String(value ?? '').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const human = (value) => String(value).replaceAll('-',' ');
const fraction = (value) => `${value.numerator}/${value.denominator}`;
const pill = (text,kind='neutral') => `<span class="pill ${kind}">${escapeHTML(text)}</span>`;
const rate = (value) => value.value == null ? 'N/A' : `${(value.value*100).toFixed(1)}%`;

function renderOverview(){
 const d=state.data,m=d.metrics,g=m['hardened-grounded'],v=m.vulnerable;
 const metrics=[
  ['Model executions',String(d.execution_count),'Actual local-model inference','↗'],
  ['Versioned scenarios',String(d.case_count),'18 attack cases · 16 benign requests','◇'],
  ['Unauthorized executions',`${v.unauthorized_tool_executions} <small>→</small> ${g.unauthorized_tool_executions}`,'Vulnerable → hardened configurations','⌁'],
  ['Benign completion',`${g.benign_completion.numerator}<small>/${g.benign_completion.denominator}</small>`,'Same total · different failed tasks','✓']
 ];
 $('#metrics').innerHTML=metrics.map(([label,value,note,icon])=>`<div class="metric"><div class="metric-label">${label}<span class="metric-icon" aria-hidden="true">${icon}</span></div><div class="metric-value">${value}</div><div class="metric-sub">${note}</div></div>`).join('');
 const rows=[
  ['Known hijacks delivered',c=>fraction(c.objective_populations['known-native-retest:hijack'].delivered_hit)],
  ['Held-out hijacks delivered',c=>fraction(c.objective_populations['held-out:hijack'].delivered_hit)],
  ['Unauthorized tool executions',c=>String(c.unauthorized_tool_executions)],
  ['Benign tasks completed',c=>fraction(c.benign_completion)],
  ['Execution errors',c=>String(c.errors)]
 ];
 $('#comparison-body').innerHTML=rows.map(([label,get])=>`<tr><td>${label}</td>${d.configurations.map((c,i)=>`<td${i===0&&label==='Execution errors'?' class="error-text"':''}>${escapeHTML(get(m[c]))}</td>`).join('')}</tr>`).join('');
 const verification=d.verification;
 const cards=[
  ['CORE REGRESSION SNAPSHOT',verification.regression_tests_passed,'Tests recorded in the later security-v2 verification. Additional dashboard tests are separate.', 'results/security-v2/pytest.log'],
  ['BOUNDARY VERIFICATION',verification.boundary_checks.passed,'Deterministic checks of roles, resources, consent, replay, concurrency and request isolation.', 'results/security-v2/verified-boundaries/report.md'],
  ['PRESERVED HISTORY',verification.historical_result_hashes_preserved,'Earlier evidence files checked against their original hashes. Failed attempts remain available.', 'results/security-v2/verification.json']
 ];
 $('#verification-cards').innerHTML=cards.map(([label,value,note,path])=>`<article class="verification-card"><span class="eyebrow">${label}</span><strong>${value}</strong><p>${note}</p><a href="${REPO+path}" target="_blank" rel="noopener noreferrer">Inspect the evidence ↗</a></article>`).join('');
 const detector=g.content_only_detection;
 $('#confusion').innerHTML=[['tp','True positives'],['fp','False positives'],['tn','True negatives'],['fn','False negatives']].map(([key,label])=>`<div><strong>${detector[key]}</strong><span>${label}</span></div>`).join('');
 $('#detector-rates').textContent=`Precision ${fraction(detector.precision)} (${rate(detector.precision)}) · Recall ${fraction(detector.recall)} (${rate(detector.recall)}) · Benign false-positive rate ${fraction(detector.false_positive_rate)} (${rate(detector.false_positive_rate)})`;
}

function objectiveHit(item,run){return item.kind==='unauthorized'?run.executions>0:run.delivered_hit;}
function outcomeLabel(item,run,grounded=false){
 if(run.error)return pill('Execution error','warn');
 if(!item.attack)return pill(run.benign_complete?'Task completed':'Task incomplete',run.benign_complete?'good':'warn');
 if(objectiveHit(item,run))return pill('Objective observed','bad');
 const original=item.runs.vulnerable;
 return pill(grounded&&objectiveHit(item,original)?'Contained in sample':'Not observed',grounded&&objectiveHit(item,original)?'good':'neutral');
}
function renderCaseRows(){
 if(!state.data)return;
 const query=$('#case-search').value.trim().toLowerCase(),type=$('#case-type').value;
 const filtered=state.data.cases.filter(c=>(type==='all'||(type==='attack'?c.attack:!c.attack))&&`${c.id} ${c.category} ${c.prompt}`.toLowerCase().includes(query));
 $('#case-count').textContent=`${filtered.length} of ${state.data.case_count} cases`;
 $('#empty-state').hidden=filtered.length>0;
 $('#case-rows').innerHTML=filtered.map(item=>`<tr class="${item.id===state.selected?'selected':''}"><td><button type="button" data-case="${item.id}"><span class="case-id">${item.id}</span><span class="case-category">${escapeHTML(human(item.category))}</span></button></td><td>${pill(item.attack?'Attack attempt':'Benign request')}</td><td>${outcomeLabel(item,item.runs.vulnerable)}</td><td>${outcomeLabel(item,item.runs['hardened-grounded'],true)}</td><td><button type="button" data-case="${item.id}" aria-label="Inspect case ${item.id}">↗</button></td></tr>`).join('');
 $('#case-rows').querySelectorAll('[data-case]').forEach(button=>button.addEventListener('click',()=>{location.hash=`cases/${button.dataset.case}`;$('#case-detail').scrollIntoView({behavior:'smooth',block:'start'});}));
}
function renderDetail(){
 const item=state.data.cases.find(c=>c.id===state.selected)||state.data.cases[0];
 state.selected=item.id;
 const run=item.runs[state.configuration],isTextObjective=['hijack','secret','instructions'].includes(item.kind);
 const stats=[
  ['Raw text objective',isTextObjective?(run.raw_hit?'Observed':'Not observed'):'Not applicable'],
  ['Delivered text objective',isTextObjective?(run.delivered_hit?'Observed':'Not observed'):'Not applicable'],
  ['Prohibited tool proposals',String(run.proposals)],
  ['Unauthorized executions',String(run.executions)]
 ];
 const events=run.events.map(event=>{
  let badge='',kind='';
  if(event.kind==='authorization'){
   badge=event.allowed?pill('Allowed','good'):pill(event.enforced?'Denied':'Shadow denial',event.enforced?'good':'warn');
   kind=event.allowed||event.enforced?'good':'bad';
  }
  if(event.kind==='tool_execution'){kind=event.unauthorized?'bad':'good';badge=pill(event.unauthorized?'Unauthorized':'Authorized',event.unauthorized?'bad':'good');}
  return `<div class="timeline-item ${kind}"><strong>${escapeHTML(event.label)}</strong>${badge}<p>${escapeHTML(event.detail)}</p></div>`;
 }).join('');
 $('#case-detail').innerHTML=`<div class="detail-heading"><div><span class="eyebrow">CASE ${item.id} / ${escapeHTML(human(item.split))}</span><h2>${escapeHTML(human(item.category))}</h2></div>${outcomeLabel(item,run,state.configuration==='hardened-grounded')}</div><div class="prompt-block"><span class="eyebrow">RECORDED USER REQUEST</span><pre>${escapeHTML(item.prompt)}</pre></div><div class="config-tabs" role="group" aria-label="Application configuration">${state.data.configurations.map(c=>`<button type="button" data-config="${c}" aria-pressed="${c===state.configuration}">${CONFIG_NAMES[c]}</button>`).join('')}</div><div class="run-stats">${stats.map(([label,value])=>`<div class="run-stat"><span>${label}</span><strong>${value}</strong></div>`).join('')}</div>${run.error?`<div class="notice error">Recorded error: ${escapeHTML(run.error)}. This is not counted as a successful defense.</div>`:''}<div class="detail-body"><div class="response-panel"><span class="eyebrow">DELIVERED RESPONSE</span><pre>${escapeHTML(run.response||'(No response delivered)')}</pre><div class="response-note">Recorded output; known synthetic protected markers redacted. Raw prompts, customer records and provider generations are omitted from this view.</div></div><div><span class="eyebrow">EXECUTION TIMELINE / ${run.events.length} SELECTED EVENTS</span><div class="timeline">${events||'<p class="muted">No execution events recorded.</p>'}</div></div></div>`;
 $('#case-detail').querySelectorAll('[data-config]').forEach(button=>button.addEventListener('click',()=>{state.configuration=button.dataset.config;renderDetail();}));
}
function route(){
 const [requested,caseId]=location.hash.replace('#','').split('/');
 const page=['overview','cases','controls','verification'].includes(requested)?requested:'overview';
 document.querySelectorAll('.view').forEach(view=>{view.hidden=view.id!==page;});
 document.querySelectorAll('[data-nav]').forEach(a=>{const active=a.dataset.nav===page;a.classList.toggle('active',active);if(active)a.setAttribute('aria-current','page');else a.removeAttribute('aria-current');});
 $('#breadcrumb').textContent={overview:'Overview',cases:'Explore cases',controls:'Security controls',verification:'Verification'}[page];
 if(page==='cases'&&state.data){if(caseId&&state.data.cases.some(c=>c.id===caseId))state.selected=caseId;renderCaseRows();renderDetail();}
}
function showReproduction(){
 $('#dialog-title').textContent='Run the checks locally.';
 $('#dialog-content').innerHTML='<p>This hosted dashboard explores recorded evidence. Run the local FastAPI dashboard to execute the current deterministic boundary suite.</p><pre>uv sync --frozen --extra dev\nuv run --frozen uvicorn app.dashboard:app --host 127.0.0.1 --port 8010</pre><p>Open <strong>http://127.0.0.1:8010</strong> and select “Run boundary checks.” The checks use scripted compromised-model fixtures and make no language-model calls.</p><a class="button primary" href="https://github.com/codeit-ronit/AI-red-teaming/blob/main/docs/dashboard.md" target="_blank" rel="noopener noreferrer">Setup instructions ↗</a>';
}
async function checkBoundaries(){
 const dialog=$('#check-dialog');dialog.showModal();
 const runtime=document.querySelector('meta[name="runtime"]').content;
 if(runtime!=='local'){showReproduction();return;}
 $('#dialog-title').textContent='Checking execution boundaries…';
 $('#dialog-content').innerHTML='<p><span class="check-spinner" aria-hidden="true"></span>Running the current deterministic suite. No live model inference.</p>';
 document.querySelectorAll('.check-button').forEach(b=>b.disabled=true);
 try{
  const response=await fetch('/api/checks',{method:'POST',headers:{'X-AgentSec-Action':'run-boundaries'}});
  if(!response.ok)throw new Error(`Check request failed (${response.status}).`);
  const result=await response.json();
  if(result.real_model!==false)throw new Error('Unexpected verification method.');
  $('#dialog-title').textContent=result.summary.failed?'Some boundaries failed.':'Boundary checks complete.';
  $('#dialog-content').innerHTML=`<div class="check-result">${result.summary.passed}<small> / ${result.summary.checks}</small></div><p>${result.summary.failed} failed. Executed now against the local Python security controls.</p><div class="result-families">${result.families.map(f=>escapeHTML(human(f))).join(' · ')}</div><p><strong>Method:</strong> deterministic compromised-model fixtures. This result verifies the tested execution boundaries; it is not a live-model attack-success estimate.</p>`;
 }catch(error){$('#dialog-title').textContent='The checks did not complete.';$('#dialog-content').innerHTML=`<p>${escapeHTML(error.message)} No successful verification result is being reported.</p><p>Check the local server and retry.</p>`;}
 finally{document.querySelectorAll('.check-button').forEach(b=>b.disabled=false);}
}

$('#case-search').addEventListener('input',renderCaseRows);
$('#case-type').addEventListener('change',renderCaseRows);
document.querySelectorAll('.check-button').forEach(b=>b.addEventListener('click',checkBoundaries));
$('#close-dialog').addEventListener('click',()=>$('#check-dialog').close());
$('#check-dialog').addEventListener('click',event=>{if(event.target===$('#check-dialog')){const rect=event.target.getBoundingClientRect();if(event.clientX<rect.left||event.clientX>rect.right||event.clientY<rect.top||event.clientY>rect.bottom)event.target.close();}});
window.addEventListener('hashchange',route);
route();
(async()=>{
 try{
  const response=await fetch('data/experiment.json');if(!response.ok)throw new Error('Evidence request failed.');
  const data=await response.json();if(data.schema_version!==1||data.cases.length!==data.case_count)throw new Error('Unsupported evidence format.');
  state.data=data;renderOverview();route();
  if(document.querySelector('meta[name="runtime"]').content!=='local')document.querySelectorAll('.check-button').forEach(b=>{b.textContent='Reproduce checks locally ↗';});
 }catch(error){$('#load-error').hidden=false;$('#metrics').innerHTML='';}
})();
