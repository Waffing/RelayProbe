import {api, setAccess, streamRun} from "./api.js";
import {$, archive, clean, esc, isReport, money, num, read, state, toast, visible, write} from "./state.js";
import {renderReport, renderComparison} from "./report.js";
import {saveFile} from "./export.js";

const physicalFields = {connect_s:"连接超时（秒）",read_s:"常规读超时（秒）",heavy_s:"重型读超时（秒）",
  max_requests:"最大请求数",max_tokens:"最大总 tokens",consecutive_failures:"单项连续失败上限",
  cache_repeats:"缓存率重复次数",sustained_rpm:"持续速率目标（RPM）"};
const ruleFields = {input_tolerance:"阶梯输入容差（tok）",output_tolerance:"可见输出容差（tok）",high_injection:"高额注入（tok）",
  high_cache:"高缓存率（0–1）",warm_ttft_ratio:"热 / 冷 TTFT 警戒比",answer_ttft_ratio:"答案缓存 TTFT 比",
  effort_ratio:"推理档位 token 增长比",duration_ratio:"推理档位耗时增长比",tail_ratio:"尾段 / 前段速度下限",
  burst_gap_s:"突发输出静默门槛（秒）",timeout_window_s:"典型断流节点容差（秒）",assumed_cache_ratio:"无单价的推演假设比",
  score_a:"A级候选分界",score_b:"B级候选分界",score_c:"C级候选分界"};
const optional = id => $(id).value.trim() === "" ? null : Number($(id).value);
const expensive = () => [...document.querySelectorAll("[data-exp]:checked")].map(x=>Number(x.dataset.exp));
const handle = fn => async e => { try { await fn(e); } catch (err) { showError(err); } };
const on = (id, fn) => { $(id).onclick=handle(fn); };
const preferences = () => state.preferences;
const modelName = () => $("model").value.trim();
let captureTimer, startPending=false;

function page() {
  const current=location.hash.slice(1);
  const tab=["work","report","history","profiles","settings"].includes(current)?current:"work";
  document.querySelectorAll(".page").forEach(s=>s.hidden=s.id!=="page-"+tab);
  document.querySelectorAll("[data-tab]").forEach(a=>{
    const active=a.dataset.tab===tab;
    a.classList.toggle("active",active);
    if(active)a.setAttribute("aria-current","page");else a.removeAttribute("aria-current");
  });
  if(tab==="report") renderReport(retest);
  if(tab==="history") historyList();
  if(tab==="settings" && !$("priceModel").value) $("priceModel").value=modelName();
  window.scrollTo(0,0);
}
window.addEventListener("hashchange",page);

function theme(value) {
  document.documentElement.dataset.theme=value;
  $("theme").textContent=value==="dark"?"☀":"☾";
  $("theme").setAttribute("aria-label",value==="dark"?"切换浅色主题":"切换深色主题");
}
theme(read("theme","dark"));
on("theme",()=>{const next=document.documentElement.dataset.theme==="dark"?"light":"dark";theme(next);write("theme",next);});
$("privacy").checked=read("privacy",true);
$("privacy").onchange=()=>{write("privacy",$("privacy").checked);renderReport(retest);historyList();};

function readiness() {
  $("start").disabled=startPending||!!state.run||!state.config||!state.selected.size||!$("base").value.trim()||!$("key").value.trim()||!modelName();
  $("abort").disabled=!state.run;
  const price=state.prices[modelName()];
  $("priceState").textContent=price?`输入 ${money(price.input)} · 缓存 ${money(price.cached)} · 输出 ${money(price.output)} / 百万 tok`:"未配置官方单价，已跳过计算";
}
["base","key","model"].forEach(id=>$(id).addEventListener("input",readiness));
function toggleProbe(id,checked) {
  if(checked) state.selected.add(id); else state.selected.delete(id);
  const optionalBox=document.querySelector(`[data-exp="${id}"]`);
  if(optionalBox) optionalBox.checked=checked;
}
function drawMatrix() {
  if(!state.config) return;
  const groups=Map.groupBy ? Map.groupBy(state.config.probes,p=>p.group) : state.config.probes.reduce((m,p)=>{
    if(!m.has(p.group))m.set(p.group,[]);m.get(p.group).push(p);return m;
  },new Map());
  $("activeCount").textContent=state.selected.size;
  $("matrix").innerHTML=[...groups].map(([name,items])=>`<div class="matrixrow"><span>${esc(name)}</span><div class="pads">${items.map(p=>
    `<button class="pad ${state.selected.has(p.id)?"on":""}" data-pad="${p.id}" aria-pressed="${state.selected.has(p.id)}" title="#${p.id} ${esc(p.name)}" aria-label="#${p.id} ${esc(p.name)}">${p.id}</button>`).join("")}</div></div>`).join("");
  $("checklist").innerHTML=[...groups].map(([name,items])=>`<div class="groupbox"><label class="groupcheck"><input type="checkbox" data-group="${esc(name)}"
    ${items.filter(p=>!p.expensive).every(p=>state.selected.has(p.id))?"checked":""}>${esc(name)}</label><div class="checkgroup">${items.map(p=>`<label class="groupcheck">
    <input type="checkbox" data-item="${p.id}" ${state.selected.has(p.id)?"checked":""}>#${p.id} ${esc(p.name)}${p.expensive?"（高开销）":""}</label>`).join("")}</div></div>`).join("");
  $("expenseNote").textContent=expensive().length?"已开启高开销项目。上下文阶梯垫料合计 424,000 tok，持续速率运行 60 秒。":"高开销项目默认关闭。";
  readiness();
}
$("matrix").onclick=e=>{
  const button=e.target.closest("[data-pad]");
  if(!button) return;
  const id=Number(button.dataset.pad), focused=button.matches(":focus-visible");
  toggleProbe(id,!state.selected.has(id));
  drawMatrix();
  if(focused) $("matrix").querySelector(`[data-pad="${id}"]`).focus();
};
$("checklist").onchange=e=>{
  if(e.target.dataset.item) toggleProbe(Number(e.target.dataset.item),e.target.checked);
  if(e.target.dataset.group) for(const p of state.config.probes.filter(p=>p.group===e.target.dataset.group && !p.expensive)) toggleProbe(p.id,e.target.checked);
  drawMatrix();
};
document.querySelectorAll("[data-exp]").forEach(box=>box.onchange=()=>{toggleProbe(Number(box.dataset.exp),box.checked);drawMatrix();});
document.querySelectorAll("[data-close]").forEach(b=>b.onclick=()=>$(b.dataset.close).close());
on("selectItems",()=>$("picker").showModal());
function mode(m) {
  state.mode=m;
  state.selected=new Set([...state.config.modes[m],...expensive()]);
  document.querySelectorAll("[data-mode]").forEach(b=>{
    const chosen=b.dataset.mode===m;
    b.classList.toggle("chosen",chosen);
    b.setAttribute("aria-pressed",String(chosen));
  });
  $("budget").value=m==="quick"?"1.00":"2.00";
  drawMatrix();
}
$("modes").onclick=e=>{const b=e.target.closest("[data-mode]");if(b && state.config) mode(b.dataset.mode);};

function target() {
  const result={base_url:$("base").value.trim(),api_key:$("key").value.trim(),proxy:$("proxy").value.trim()||null};
  if($("networkCompat").checked) result.local_network_compat=true;
  return result;
}
function showError(err) {
  if(err.code==="local_network_compat" && state.config?.local_network_compat) {
    $("networkHelp").hidden=false;
    $("networkNotice").textContent=err.message;
  } else toast(err.message);
}
["base","proxy","networkCompat"].forEach(id=>$(id).addEventListener("input",()=>{$("networkHelp").hidden=true;}));
on("useNetworkCompat",()=>{
  $("networkCompat").checked=true;
  $("connectionOptions").open=true;
  $("networkHelp").hidden=true;
  $("networkCompat").focus();
  toast($("key").value ? "本机网络兼容已开启，请重试。" : "本机网络兼容已开启，请重新输入密钥。");
});
on("getModels",async()=>{
  if(!target().api_key||!target().base_url) throw new Error("请先填写 Base URL 和 API Key。");
  const b=$("getModels");b.disabled=true;
  try {
    const out=await api("/api/models",target());
    $("models").replaceChildren(...out.models.map(v=>new Option(v,v)));
    if(!modelName() && out.models.length) $("model").value=out.models[0];
    toast(`取得 ${out.models.length} 个模型`);readiness();
  } finally {b.disabled=false;}
});
function log(text) {
  const node=$("logs");
  node.append(document.createTextNode(text+"\n"));node.scrollTop=node.scrollHeight;
}
async function start() {
  if($("start").disabled) return;
  startPending=true;readiness();
  let created;
  try {
    const payload={...target(),name:$("channel").value.trim()||"未命名渠道",model:modelName(),protocol:$("protocol").value,
      profile_id:$("profile").value,bare:$("bare").checked,mode:state.mode,probe_ids:[...state.selected],expensive:expensive(),allow_50:$("allow50").checked,
      advertised_cache:optional("advertised"),panel_units_per_usd:optional("quota"),prices:state.prices[modelName()]??null,
      ledger:{kind:$("kind").value,before:optional("before"),units_per_usd:optional("units")??1},
      controls:{...preferences().controls,budget_usd:optional("budget")},fingerprints:preferences().fingerprints};
    try {created=await api("/api/runs",payload);}
    finally {payload.api_key="";payload.proxy=null;$("key").value="";$("proxy").value="";}
    state.run=created.run_id;readiness();
    $("logs").textContent="";$("progress").value=0;
    log(`预计 ${created.estimate.requests_approx} 次请求，约 ${num(created.estimate.tokens_approx,0)} tok。${created.estimate.basis}`);
    await watch();
  } finally {startPending=false;readiness();}
}
async function watch() {
  try {
    await streamRun(state.run,(type,data)=>{
      if(type==="log"||type==="reconnect") log(data.message);
      if(type==="sample") {
        log(`#${data.seq} ${data.label} · ${data.status??"无状态"} · ${num(data.elapsed,3)}s${data.error?" · "+data.error:""}`);
        $("liveStats").textContent=`${data.sent} 次已发 · ${num(data.tokens,0)} tok · ${money(data.cost)}`;
      }
      if(type==="progress") { $("progress").max=data.total||1;$("progress").value=data.done; }
      if(type==="report") {
        state.report=data;state.run=null;readiness();
        try {archive(data);} catch {toast("本地历史容量不足，本轮完整报告仍可导出。");}
        $("liveStats").textContent=data.meta.stop||`已完成 ${data.totals.requests} 次请求`;
        if(!data.meta.stop)$("progress").value=$("progress").max;
        if(location.hash==="#report")renderReport(retest);else location.hash="report";
      }
    });
  } catch(err) {
    log(err.message);toast("事件流已断开，可以恢复读取或中止当前任务。");
    if(state.run) {
      const b=document.createElement("button");b.textContent="恢复读取";b.onclick=()=>{b.remove();watch();};$("logs").append(b);
    }
  }
}
on("start",start);
on("abort",async()=>{if(state.run){await api(`/api/runs/${state.run}/abort`,{});toast("中止请求已处理");}});
function retest(ids) {
  const m=state.report.meta;
  $("channel").value=m.name;
  $("base").value=m.base_url && !m.base_url.includes("[已隐藏]") ? m.base_url : "";
  $("model").value=m.model;$("protocol").value=m.requested_protocol||"auto";$("bare").checked=m.mode_bare;
  if(state.profiles.some(p=>p.id===m.profile_id))$("profile").value=m.profile_id;
  mode(m.mode);
  state.selected.clear();document.querySelectorAll("[data-exp]").forEach(e=>e.checked=false);
  ids.forEach(i=>toggleProbe(i,true));drawMatrix();location.hash="work";
  if($("key").value && !$("start").disabled) start().catch(showError);
  else {
    ($("base").value ? $("key") : $("base")).focus();
    toast(`已勾选 ${ids.length} 个复测项，${$("base").value?"输入本轮密钥":"补填脱敏报告的地址和本轮密钥"}后即可开始。`);
  }
}

function priceList() {
  $("prices").innerHTML=Object.entries(state.prices).map(([m,p],i)=>`<div class="historyrow"><strong>${esc(m)}</strong>
    <span>${money(p.input)} / ${money(p.cached)} / ${money(p.output)}</span><button data-price="${i}">编辑</button><button data-dropprice="${i}">删除</button></div>`).join("")||'<p class="hint">未配置模型单价。</p>';
  readiness();
}
on("savePrice",()=>{
  const model=$("priceModel").value.trim(), vals=["priceIn","priceCached","priceOut"].map(optional);
  if(!model||vals.some(v=>v===null||!Number.isFinite(v)||v<0))throw new Error("请填写模型标识及三项非负单价。");
  state.prices={...state.prices,[model]:{input:vals[0],cached:vals[1],output:vals[2]}};
  write("prices",state.prices);priceList();toast("模型价格已保存");
});
$("prices").onclick=e=>{
  const {price,dropprice}=e.target.dataset;
  const key=Object.keys(state.prices)[Number(price??dropprice)];
  if(price!==undefined){const p=state.prices[key];$("priceModel").value=key;$("priceIn").value=p.input;$("priceCached").value=p.cached;$("priceOut").value=p.output;}
  if(dropprice!==undefined){delete state.prices[key];write("prices",state.prices);priceList();}
};
function settings() {
  const {controls,fingerprints}=preferences();
  const fields=(names,values)=>Object.entries(names).map(([k,label])=>`<label>${esc(label)}<input id="opt-${k}" type="number" step="any" value="${esc(values[k])}" required></label>`).join("");
  $("controls").innerHTML=fields(physicalFields,controls);
  $("rules").innerHTML=fields(ruleFields,controls.rules);
  $("weights").value=controls.weights.join(", ");$("fingerprints").value=fingerprints.join(", ");
  $("physical").textContent=`未配置价格时最多 ${controls.max_requests} 次请求、${num(controls.max_tokens,0)} tok。`;
  const pending=["评分边界与提示阈值采用草案值，可在本页调整。","BPS 规则待对照确切指纹。","初始指纹 4233、4157 来源为规格所述 2026-11 三家实测，待独立验证。",
    "官方模型单价与面板原始额度换算率由使用者确认。","缓存归属只可从总量推导上下界，实扣折扣需要独占账本窗口。"];
  $("pendingSettings").innerHTML=pending.map(x=>`<li>${esc(x)}</li>`).join("");
}
on("saveRules",()=>{
  const numbers=names=>Object.fromEntries(Object.keys(names).map(k=>[k,optional("opt-"+k)]));
  const list=id=>$(id).value.split(/[,，\s]+/).filter(Boolean).map(Number);
  const controls={...preferences().controls,...numbers(physicalFields),rules:numbers(ruleFields),weights:list("weights")};
  const fingerprints=list("fingerprints");
  if(controls.weights.length!==5||controls.weights.some(x=>!Number.isFinite(x)||x<0)||!controls.weights.some(x=>x>0)||fingerprints.some(x=>!Number.isInteger(x)||x<0))
    throw new Error("请检查五个非负权重及整数指纹。");
  if(Object.values(controls.rules).some(x=>x==null||!Number.isFinite(x))||Object.keys(physicalFields).some(k=>!(controls[k]>0)))throw new Error("请检查运行数值。");
  state.preferences={controls,fingerprints};write("preferences",state.preferences);settings();toast("运行配置已保存");
});

async function loadProfiles(preferred="") {
  const current=$("profile").value;
  state.profiles=await api("/api/profiles");
  for(const id of ["profile","editProfile"]) $(id).replaceChildren(...state.profiles.map(p=>new Option(`${p.name} · ${p.baseline_tokens} tok`,p.id)));
  const valid=x=>state.profiles.some(p=>p.id===x);
  $("profile").value=valid(preferred)?preferred:valid(current)?current:"builtin";
  $("editProfile").value=$("profile").value;editProfile();
}
function editProfile() {
  const p=state.profiles.find(p=>p.id===$("editProfile").value);
  $("profileJson").value=JSON.stringify(p,null,2);$("removeProfile").disabled=p?.id==="builtin";
}
$("editProfile").onchange=editProfile;
on("saveProfile",async()=>{const p=await api("/api/profiles",JSON.parse($("profileJson").value));await loadProfiles(p.id);toast("Profile 已保存");});
on("downloadProfile",()=>saveFile("relay-profile.json",JSON.stringify(state.profiles.find(p=>p.id===$("editProfile").value),null,2)));
on("removeProfile",async()=>{const id=$("editProfile").value;if(id!=="builtin"&&confirm("删除此本地 Profile？")){await api(`/api/profiles/${encodeURIComponent(id)}`,undefined,"DELETE");await loadProfiles();}});
on("importProfile",async()=>{let raw=$("rawProfile").value;try{const p=await api("/api/profiles",{raw});await loadProfiles(p.id);toast("已保存脱敏 Profile");}finally{raw="";$("rawProfile").value="";}});
$("capturePath").textContent=location.origin+"/api/capture/v1";
on("arm",async()=>{
  const x=await api("/api/capture/arm",{}),baseIds=new Set(state.profiles.map(p=>p.id)),end=Date.now()+x.expires_in*1000;
  $("captureInfo").textContent=`五分钟有效的抓包口令 ${x.token}`;
  clearInterval(captureTimer);
  captureTimer=setInterval(async()=>{
    if(Date.now()>=end){clearInterval(captureTimer);$("captureInfo").textContent="本次抓包窗口已到期。";return;}
    try{
      const list=await api("/api/profiles");
      const next=list.find(p=>!baseIds.has(p.id)&&p.source==="实机抓包复刻");
      if(next){clearInterval(captureTimer);$("captureInfo").textContent=`已捕获 ${next.name} · ${next.baseline_tokens} tok`;await loadProfiles(next.id);}
    }catch{clearInterval(captureTimer);$("captureInfo").textContent="抓包状态读取中断，请刷新模板库。";}
  },2000);
});

function historyList() {
  const list=$("historyList");
  list.innerHTML=state.history.map((r,i)=>`<div class="historyrow"><input type="checkbox" data-compare="${i}" aria-label="对比 ${esc(r.meta.name)}" ${state.comparison.has(r.run_id)?"checked":""}>
    <strong>${esc(r.meta.name)}</strong><span>${esc(r.meta.start)} · ${esc(r.meta.period)} · ${esc(r.verdict.label)}</span>
    <button data-recall="${i}">回看</button><button data-del="${i}" class="danger">删除</button></div>`).join("")||'<p class="hint">尚无本地报告。</p>';
  renderComparison();
}
$("historyList").onchange=e=>{if(e.target.dataset.compare!==undefined){const r=state.history[Number(e.target.dataset.compare)];
  if(e.target.checked)state.comparison.add(r.run_id);else state.comparison.delete(r.run_id);renderComparison();}};
$("historyList").onclick=e=>{
  if(e.target.dataset.recall!==undefined){state.report=state.history[Number(e.target.dataset.recall)];location.hash="report";}
  if(e.target.dataset.del!==undefined&&confirm("删除此本地报告？")){state.history.splice(Number(e.target.dataset.del),1);write("history",state.history);historyList();}
};
on("clearHistory",()=>{if(confirm("清空当前浏览器的全部历史报告？")){state.history=[];state.comparison.clear();write("history",[]);historyList();}});
on("exportHistory",()=>saveFile("relay-probe-history.json",JSON.stringify(state.history.map(r=>visible(r,$("privacy").checked)),null,2)));
$("importHistory").onchange=handle(async()=>{
  const f=$("importHistory").files[0];if(!f)return;
  try{
    const data=JSON.parse(await f.text()),rows=Array.isArray(data)?data:[data];
    if(!rows.every(isReport))throw new Error("文件包含无效的报告结构。");
    for(const r of rows.slice().reverse())archive(clean(r));historyList();toast(`已导入 ${rows.length} 条报告`);
  }finally{$("importHistory").value="";}
});

async function boot() {
  try {
    state.config=await api("/api/config");
    $("localNetwork").hidden=!state.config.local_network_compat;
    if(!state.config.local_network_compat)$("networkCompat").checked=false;
    $("connection").textContent="服务已连接";$("connection").classList.add("online");
    if($("auth").open)$("auth").close();
    const stored=read("preferences",{});
    state.preferences={controls:{...state.config.controls,...stored.controls,rules:{...state.config.controls.rules,...stored.controls?.rules}},
      fingerprints:stored.fingerprints??[4233,4157]};
    state.history=read("history",[]).filter(isReport);state.prices=read("prices",{});
    await loadProfiles();mode("quick");settings();priceList();page();
  }catch(err){
    $("connection").textContent=err.status===401?"需要口令":"连接失败";
    if(err.status===401){if(!$("auth").open)$("auth").showModal();$("authMessage").textContent="此服务已启用访问口令。";}
    else toast(err.message);
  }
}
$("authForm").onsubmit=e=>{e.preventDefault();setAccess($("password").value);$("password").value="";boot();};
boot();
