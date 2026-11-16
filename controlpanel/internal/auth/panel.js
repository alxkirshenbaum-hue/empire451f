"use strict";
(() => {
 const byId = id => document.getElementById(id);
 const csrf = document.querySelector('meta[name="csrf-token"]')?.content;
 if (!csrf) return;
 const pendingKey = "vpn-control.pending-intent";
 const stateLabels={active:"Active",disabled:"New connections revoked",provisioning:"Provisioning",deleted:"Deleted",queued:"Queued",running:"Applying",verifying:"Verifying",succeeded:"Completed",failed:"Failed",cancelled:"Cancelled",rollback_running:"Restoring",rolled_back:"Restored",reconcile_required:"Unconfirmed"};
 const stateLabel=value=>stateLabels[value]||value;
 const kindLabels={"user.create":"Create user","user.disable":"Revoke new connections","user.enable":"Enable user","user.delete":"Delete user","credential.rotate":"Rotate credential","user.rename":"Rename user"};
 const kindLabel=value=>kindLabels[value]||value;
 const state = {cap:null,user:null,ops:[],cursor:"",previous:[],next:"",poll:null,unknown:null};
 const node = (tag,text,cls) => {const n=document.createElement(tag);if(text!==undefined)n.textContent=String(text);if(cls)n.className=cls;return n;};
 const empty = n => n.replaceChildren();
 const message = text => {byId("message").textContent=text;};
 const report = error => {const n=byId("failure");n.hidden=false;n.textContent=error.message||"Request unavailable.";};
 const clearError = () => {byId("failure").hidden=true;};
 const dates = value => {
  if(!value)return "Not recorded";
  // SQLite CURRENT_TIMESTAMP is UTC even though it has no timezone suffix.
  const utc=/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?$/.test(value)?value.replace(" ","T")+"Z":value;
  const date=new Date(utc);
  return Number.isFinite(date.getTime())?date.toLocaleString():"Unknown timestamp";
 };
 function savePending(record) {
  if(record){
   try{sessionStorage.setItem(pendingKey,JSON.stringify(record));}catch(_){throw new Error("Session storage is required for safe request recovery.");}
  }else{sessionStorage.removeItem(pendingKey);}
  state.unknown=record;
  byId("retry-request").hidden=!record;
  applyAvailability();
 }
 function restorePending() {
  try {
   const record=JSON.parse(sessionStorage.getItem(pendingKey));
   const allowed=/^\/api\/v1\/users(?:\/[0-9a-f-]{36}(?:\/(?:disable|enable|credential\/(?:rotate|revoke)))?)?$/;
   const fields=new Set(["login","display_name","template_revision_id","target_client","expected_version","reason","confirm_delete"]);
   if(record && allowed.test(record.path) && ["POST","PATCH","DELETE"].includes(record.method) &&
      /^[0-9a-f-]{36}$/.test(record.key) && record.body && Object.keys(record.body).every(k=>fields.has(k))) {
    state.unknown=record;byId("retry-request").hidden=false;
    message("An earlier request has an unconfirmed result. Retry its original intent to recover the receipt.");
   } else sessionStorage.removeItem(pendingKey);
  } catch (_) {sessionStorage.removeItem(pendingKey);}
 }
 async function api(path,method="GET",body,key) {
  if(!path.startsWith("/api/v1/") || path.includes("//"))throw new Error("Invalid local API path.");
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),12000);
  try {
   const headers={"Accept":"application/json"};
   if(method!=="GET") {headers["Content-Type"]="application/json";headers["X-CSRF-Token"]=csrf;if(key)headers["Idempotency-Key"]=key;}
   const response=await fetch(path,{method,headers,body:body===undefined?undefined:JSON.stringify(body),credentials:"same-origin",cache:"no-store",signal:controller.signal});
   if(response.status===204)return null;
   let envelope;
   try {envelope=await response.json();}catch(_){const e=new Error("Invalid API response.");e.status=response.ok?0:response.status;throw e;}
   if(!response.ok) {
    if(response.status===401){sessionStorage.removeItem(pendingKey);location.assign("/");}
    const e=new Error(envelope.error?.code||"Request unavailable.");e.status=response.status;throw e;
   }
   return envelope.data;
  } finally {clearTimeout(timer);}
 }
 function pendingUser(id) {
  return state.ops.some(op=>op.target_id===id&&["queued","running","verifying","rollback_running","reconcile_required"].includes(op.status));
 }
 function applyAvailability() {
  const enabled=!!state.cap?.mutations_enabled&&!state.unknown;
  byId("create-button").disabled=!enabled||!byId("template-select").options.length;
  if(state.user) {
   const enabledUser=enabled&&!state.user.protected&&!pendingUser(state.user.id)&&["active","disabled"].includes(state.user.status);
   byId("rename-user").querySelector("button").disabled=!enabledUser;
   for(const button of byId("user-actions").querySelectorAll("button"))button.disabled=!enabledUser;
  }
 }
 async function change(record) {
  if(!record) return;
  clearError();savePending(record);
  let result;
  try {
   result=await api(record.path,record.method,record.body,record.key);
   if(!result?.operation_id)throw new Error("Operation receipt is missing.");
  } catch(error) {
   if(error.status && error.status<500)savePending(null);
   else message("The request outcome is unknown. Retry the original request; it will reuse the same intent.");
   throw error;
  }
  savePending(null);message("Operation queued: "+result.operation_id);
  location.hash="operations";await loadOperations();
  await showOperation(result.operation_id);
  if(record.path==="/api/v1/users")byId("create-user").reset();
 }
 function submitChange(method,path,body) {
  if(state.unknown)return Promise.reject(new Error("Recover the original request before submitting another change."));
  if(!crypto.randomUUID)return Promise.reject(new Error("A secure browser context is required for changes."));
  return change({method,path,body,key:crypto.randomUUID()});
 }
 function renderResources(data) {
  const list=byId("local-resources");empty(list);
  const add=(label,value)=>list.append(node("dt",label),node("dd",value));
  const counter=value=>Number.isSafeInteger(value)&&value>=0?new Intl.NumberFormat().format(value):"Unknown";
  const bytes=value=>counter(value)+(Number.isSafeInteger(value)&&value>=0?" bytes":"");
  const usable=sample=>sample?.state==="observed" && Number.isFinite(Date.parse(sample.observed_at)) && Date.parse(sample.observed_at)<=Date.now()+5000 && Date.parse(sample.stale_after)>Date.now();
  for(const [label,key] of [["OS CPU busy (interval)","cpu"],["OS memory","memory"],["Load average (1 minute, not CPU %)","load"],["Registry filesystem","storage"],["Namespace network counters","network"]]) {
   const sample=data?.[key];
   if(!usable(sample)){add(label,sample?.state==="observed"?"Stale — refresh required":"Unknown");continue;}
   if(key==="memory")add(label,bytes(sample.values?.available_bytes)+" available / "+bytes(sample.values?.total_bytes)+" total");
   if(key==="cpu")add(label,Number.isFinite(sample.usage_percent)&&sample.usage_percent>=0&&sample.usage_percent<=100?sample.usage_percent.toFixed(1)+"% over "+counter(sample.interval_ms)+" ms (idle and iowait excluded)":"Unknown");
   if(key==="load")add(label,Number.isFinite(sample.load_average_1m)?sample.load_average_1m:"Unknown");
   if(key==="storage"){add(label,bytes(sample.values?.filesystem_available_bytes)+" available / "+bytes(sample.values?.filesystem_total_bytes)+" total");add("Registry DB/WAL/SHM allocated (not whole panel)",bytes(sample.values?.registry_allocated_bytes));}
   if(key==="network"){
    add(label,sample.namespace||"Unknown namespace");
    for(const entry of sample.interfaces||[]){
     for(const [direction,key] of [["RX","receive"],["TX","transmit"]]){
      const values=entry[key];add(entry.name+" "+direction,bytes(values?.bytes)+" · "+counter(values?.packets)+" packets · "+counter(values?.errors)+" errors · "+counter(values?.dropped)+" dropped");
     }
    }
   }
   add(label+" source",sample.source+" · "+dates(sample.observed_at));
  }
  byId("resource-time").textContent="Local ingress OS and collector network namespace only. Network counters include loopback and do not identify VPN traffic or physical interfaces. No VPN/exit health or total panel footprint is inferred.";
 }
 let resourceSnapshot=null;
 async function loadResources(){resourceSnapshot=await api("/api/v1/system/resources");renderResources(resourceSnapshot);}
 setInterval(()=>{if(resourceSnapshot)renderResources(resourceSnapshot);},10000);
 async function loadCounts() {
  const data=await api("/api/v1/dashboard");
  byId("regular-count").textContent=data.counts.regular+" / 100";
  byId("protected-count").textContent=data.counts.protected;
  byId("pending-count").textContent=data.counts.pending;
 }
 async function loadUsers(reset=false) {
  if(reset){state.cursor="";state.previous=[];}
  const query=new URLSearchParams({limit:"100",search:byId("search").value,status:byId("status-filter").value});
  if(state.cursor)query.set("cursor",state.cursor);
  const data=await api("/api/v1/users?"+query);
  state.next=data.next_cursor;
  const tbody=byId("users-body");empty(tbody);
  for(const user of data.users) {
   const row=node("tr"),identity=node("td"),name=node("div",user.login,"mono");
   identity.append(name,node("div",user.display_name,"muted"));row.append(identity);
   const status=node("td");status.append(node("span",stateLabel(user.status),"badge"));row.append(status,node("td",user.protected?"Protected":"Regular"));
   const action=node("td"),open=node("button","Open","quiet");open.addEventListener("click",()=>showUser(user.id).catch(report));action.append(open);row.append(action);tbody.append(row);
  }
  if(!data.users.length){const row=node("tr"),cell=node("td","No matching users.");cell.colSpan=4;row.append(cell);tbody.append(row);}
  byId("next-users").disabled=!state.next;byId("previous-users").disabled=!state.previous.length;
  await loadCounts();
 }
 async function showUser(id) {
  const [data,history]=await Promise.all([api("/api/v1/users/"+id),api("/api/v1/users/"+id+"/history")]);
  const changed=state.user?.id!==id;state.user=data.user;
  byId("user-detail").hidden=false;byId("user-heading").textContent=data.user.login;
  const metadata=byId("user-metadata");empty(metadata);
  for(const [label,value] of [["Recorded state",stateLabel(data.user.status)],["Account type",data.user.protected?"Protected":"Regular"],["Row version",data.user.row_version],["Credential version",data.credential.secret_version],["Live state","Not measured"],["Existing tunnels","Termination not confirmed"]])metadata.append(node("dt",label),node("dd",value));
  byId("rename-user").elements.display_name.value=data.user.display_name;
  const actions=byId("user-actions");empty(actions);
  if(!data.user.protected && ["active","disabled"].includes(data.user.status)) {
   for(const action of (data.user.status==="active"?["disable","rotate","delete"]:["enable","delete"])) {
    const button=node("button",({disable:"Revoke new connections",enable:"Enable",rotate:"Rotate credential",delete:"Delete"})[action],action==="delete"?"danger":"quiet");
    button.addEventListener("click",()=>mutateUser(action).catch(report));actions.append(button);
   }
  } else if(data.user.protected)actions.append(node("p","Protected account. Ordinary changes are unavailable.","help"));
  const list=byId("user-history");empty(list);
  for(const op of history){const link=node("a",kindLabel(op.kind)+" · "+stateLabel(op.status)+" · "+dates(op.created_at));link.href="#operations";link.addEventListener("click",()=>showOperation(op.operation_id).catch(report));const line=node("p");line.append(link);list.append(line);}
  if(!history.length)list.append(node("p","No owner operations recorded.","help"));
  if(changed){byId("profile-client").value="sfa-1.14.4";byId("profile-optional").checked=false;}
  updateDownload();applyAvailability();
 }
 function updateDownload() {
  const alpha=byId("profile-client").value==="sfa-1.15-alpha13",option=byId("profile-optional");
  if(!alpha&&option.checked){option.checked=false;message("Optional routing was turned off for the selected base-only version.");}
  option.disabled=!alpha;
  const user=state.user,link=byId("download-profile");
  const available=user?.status==="active"&&!pendingUser(user.id);
  link.hidden=!available;
  if(available){
   const query=new URLSearchParams({client:byId("profile-client").value});
   if(option.checked){query.set("ru_dm","1");query.set("ack","1");}
   link.href="/api/v1/users/"+user.id+"/profiles/download?"+query;
  } else link.removeAttribute("href");
  byId("profile-state").textContent=available?"Base routing is used unless the optional feature is selected.":"A profile is available only after the account is confirmed active.";
 }
 async function mutateUser(action) {
  const user=state.user;
  if(!user||user.protected)throw new Error("Protected account.");
  if(action==="delete"&&!confirm("Delete "+user.login+"? The login stays reserved. New connections will be denied; existing tunnels may remain open."))return;
  if(action==="rotate"&&!confirm("Rotate "+user.login+"? Download a new profile after success. Existing tunnels may remain open."))return;
  const reason=prompt(action==="enable"?"Reason (optional)":"Reason for this change");
  if(reason===null)return;
  if(action!=="enable"&&!reason.trim())throw new Error("A reason is required.");
  const suffix=action==="rotate"?"/credential/rotate":action==="delete"?"":"/"+action;
  await submitChange(action==="delete"?"DELETE":"POST","/api/v1/users/"+user.id+suffix,{expected_version:user.row_version,reason,confirm_delete:action==="delete"});
 }
 async function loadOperations() {
  state.ops=await api("/api/v1/operations");
  const tbody=byId("operations-body");empty(tbody);
  for(const op of state.ops){
   const row=node("tr"),cell=node("td"),link=node("a",op.operation_id.slice(0,12),"mono");link.href="#operations";link.title=op.operation_id;
   link.addEventListener("click",()=>showOperation(op.operation_id).catch(report));cell.append(link);row.append(cell,node("td",kindLabel(op.kind)),node("td",stateLabel(op.status)),node("td",dates(op.created_at)));tbody.append(row);
  }
  if(!state.ops.length){const row=node("tr"),cell=node("td","No owner operations recorded.");cell.colSpan=4;row.append(cell);tbody.append(row);}
  applyAvailability();updateDownload();
 }
 async function showOperation(id) {
  if(state.poll)clearTimeout(state.poll);
  const op=await api("/api/v1/operations/"+id),detail=byId("operation-detail");detail.hidden=false;empty(detail);
  detail.append(node("h2",kindLabel(op.kind)),node("p",op.operation_id,"mono"),node("p","Recorded state: "+(op.status==="reconcile_required"?"Needs SSH reconciliation":stateLabel(op.status))));
  const timeline=node("ol");
  for(const step of op.steps||[])timeline.append(node("li",step.name+" · "+step.state+(step.error_code?" · "+step.error_code:"")));
  if(!timeline.children.length)detail.append(node("p","No step receipts recorded.","help"));else detail.append(timeline);
  if(op.status==="reconcile_required")detail.append(node("p","Changes are blocked. An administrator must inspect and reconcile this operation through SSH.","notice"));
  if(["queued","running","verifying","rollback_running"].includes(op.status)){
   state.poll=setTimeout(()=>showOperation(id).catch(report),3000);
  } else {
   await Promise.all([loadOperations(),loadUsers()]);
   if(state.user)await showUser(state.user.id);
  }
 }
 async function loadInventories() {
  const summary=byId("evidence-summary");
  empty(summary);summary.append(node("dt","Registry records"),node("dd","Refreshing — previous timestamps are not current"));
  const [audits,backups]=await Promise.all([api("/api/v1/audits"),api("/api/v1/backups")]);
  const a=byId("audit-list"),b=byId("backup-list");empty(a);empty(b);
  empty(summary);
  const add=(label,value)=>summary.append(node("dt",label),node("dd",value));
  add("Source","Local panel registry; bounded stored records");
  const latestAudit=audits[0],latestBackup=backups[0];
  add("Latest audit activity started",dates(latestAudit?.started_at));
  add("Latest audit activity finished",dates(latestAudit?.finished_at));
  add("Checks in that record",latestAudit?latestAudit.checks:"Not recorded");
  add("Latest backup created",dates(latestBackup?.created_at));
  add("Latest backup recorded state",latestBackup?.status||"Not recorded");
  add("That backup last verified",dates(latestBackup?.verified_at));
  add("Records fetched",new Date().toLocaleString());
  for(const audit of audits){const card=node("div",undefined,"card");card.append(node("h3",audit.id),node("p","Started: "+dates(audit.started_at)),node("p","Finished: "+dates(audit.finished_at)),node("p","Recorded checks: "+audit.checks));a.append(card);}
  if(!audits.length)a.append(node("p","No audit reports recorded.","help"));
  for(const backup of backups){const card=node("div",undefined,"card");card.append(node("h3",backup.id),node("p",backup.status+" · "+backup.size_bytes+" bytes"),node("p","Created: "+dates(backup.created_at)),node("p","Generation: "+backup.source_generation),node("p","Stored verification: "+dates(backup.verified_at)));b.append(card);}
  if(!backups.length)b.append(node("p","No backup records available.","help"));
 }
 function navigate() {
  const tabs=["dashboard","users","operations","audits","backups","system"],tab=tabs.includes(location.hash.slice(1))?location.hash.slice(1):"dashboard";
  for(const name of tabs)byId("view-"+name).hidden=name!==tab;
  for(const link of document.querySelectorAll("nav a"))if(link.hash==="#"+tab)link.setAttribute("aria-current","page");else link.removeAttribute("aria-current");
 }
 byId("owner-password").addEventListener("submit",async event=>{
  event.preventDefault();const form=event.currentTarget,button=form.querySelector("button");
  const values=Object.fromEntries(new FormData(form).entries());
  const byteLength=new TextEncoder().encode(values.new_password).length;
  if(byteLength<12||byteLength>1024){form.reset();report(new Error("New password must contain 12 to 1024 bytes."));return;}
  if(values.new_password!==values.confirm_password){form.reset();report(new Error("New passwords do not match."));return;}
  button.disabled=true;
  try{await api("/api/v1/auth/change-password","POST",values);form.reset();location.assign("/");}
  catch(error){form.reset();report(error);}finally{button.disabled=false;}
 });
 byId("create-user").addEventListener("submit",event=>{
  event.preventDefault();const form=new FormData(event.currentTarget);
  submitChange("POST","/api/v1/users",Object.fromEntries(form.entries())).catch(report);
 });
 byId("rename-user").addEventListener("submit",event=>{
  event.preventDefault();if(!state.user)return;
  submitChange("PATCH","/api/v1/users/"+state.user.id,{display_name:event.currentTarget.elements.display_name.value,expected_version:state.user.row_version}).catch(report);
 });
 byId("retry-request").addEventListener("click",()=>change(state.unknown).catch(report));
 byId("refresh-resources").addEventListener("click",()=>loadResources().catch(report));
 byId("refresh-evidence").addEventListener("click",()=>loadInventories().catch(report));
 byId("refresh-users").addEventListener("click",()=>loadUsers().catch(report));
 byId("refresh-operations").addEventListener("click",()=>loadOperations().catch(report));
 byId("next-users").addEventListener("click",()=>{state.previous.push(state.cursor);state.cursor=state.next;loadUsers().catch(report);});
 byId("previous-users").addEventListener("click",()=>{state.cursor=state.previous.pop()||"";loadUsers().catch(report);});
 let searchTimer;byId("search").addEventListener("input",()=>{clearTimeout(searchTimer);searchTimer=setTimeout(()=>loadUsers(true).catch(report),250);});
 byId("status-filter").addEventListener("change",()=>loadUsers(true).catch(report));
 byId("profile-client").addEventListener("change",updateDownload);byId("profile-optional").addEventListener("change",updateDownload);
 addEventListener("hashchange",navigate);navigate();restorePending();
 (async()=>{
  const [cap,templates,identity]=await Promise.all([api("/api/v1/capabilities"),api("/api/v1/templates"),api("/api/v1/auth/me")]);
  byId("owner-identity").textContent="Owner: "+identity.username+" · Session expires: "+dates(identity.expires_at);
  state.cap=cap;byId("routing-warning").textContent=cap.routing_warning;
  for(const template of templates){const option=node("option",template.name+" · "+template.variant);option.value=template.id;byId("template-select").append(option);}
  if(!cap.mutations_enabled)message("Management is read only for this installation.");
  applyAvailability();await Promise.all([loadUsers(),loadOperations(),loadInventories(),loadResources()]);
 })().catch(report);
})();
