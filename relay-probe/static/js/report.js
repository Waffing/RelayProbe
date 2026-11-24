import { $, archive, esc, money, num, pct, state, toast, visible } from "./state.js";
import { exportReport, sixValues } from "./export.js";

const groups = [[1,5,"检测项（计分）"],[6,10,"请求质量（不计分）"],[11,15,"验账与计费"],[16,20,"缓存深度"],
  [21,27,"科技签名"],[28,36,"模型与 Codex 实战"],[37,40,"并发压测"]];
const mark = v => ["异常","红"].includes(v) ? "bad" : ["需关注","证据不足","黄"].includes(v) ? "warn" : "";
const badge = text => `<span class="badge ${mark(text)}">${esc(text)}</span>`;
const metric = (label,value,detail="") => `<div class="kpi"><small>${esc(label)}</small><strong>${esc(value)}</strong><p>${esc(detail)}</p></div>`;
const raw = value => `<pre>${esc(JSON.stringify(value,null,2))}</pre>`;
const ids = arr => arr.map(n=>`<button class="seqjump" data-seq="${Number(n)}">#${Number(n)}</button>`).join(" ");
const shown = () => visible(state.report, $("privacy").checked);
const multiplier = r => r.head.effective_multiplier == null ? (r.meta.prices ? "待对账" : "未配置") : num(r.head.effective_multiplier,4)+"×";
const attrs = arr => arr.map(s=>`<th>${esc(s)}</th>`).join("");
const date = v => new Date(v).toLocaleString("zh-CN", {hour12:false});

export function recalculate(r, before, after, kind, units) {
  const l = r.meta.ledger = {before,after,kind,units_per_usd:units};
  const auto = r.findings.find(f=>f.id===15);
  const a = auto?.metrics.before, b = auto?.metrics.after;
  let debit = null;
  if (before != null && after != null && units > 0) debit = (after-before)*(kind==="used"?1:-1)/units;
  else if (a && b && ["kind","factor","path","field"].every(k=>a[k]===b[k])) debit=(b.usd-a.usd)*(a.kind==="used"?1:-1);
  if (debit < 0) debit = null;
  const basis = r.totals.unknown_cost ? null : r.totals.cost;
  r.head.deduction_usd = debit;
  r.head.effective_multiplier = basis > 0 && debit != null ? debit/basis : null;
  if (auto) {
    Object.assign(auto.metrics,{deduction_usd:debit,effective_multiplier:r.head.effective_multiplier,manual_ledger:l});
    auto.summary = r.head.effective_multiplier != null ? `整轮实扣 ${money(debit)}，有效倍率 ${multiplier(r)}` :
      r.meta.prices ? "余额数据或计费样本不足" : "未配置官方单价，已跳过计算";
    auto.status = r.head.effective_multiplier == null ? "证据不足" : "通过";
    const reason = r.verdict.reasons.find(x=>x.id===15);
    if (reason) reason.text=auto.summary;
  }
}

function sectionFindings(r, lo, hi, name) {
  const matches = r.findings.filter(f=>f.id>=lo && f.id<=hi);
  if (!matches.length) return "";
  return `<article class="card reportsection"><h2>${name}</h2>${matches.map(f=>`<details class="finding" id="finding-${f.id}">
    <summary><span class="numeric">#${f.id}</span> ${esc(f.name)} ${badge(f.status)}</summary>
    <p>${esc(f.summary)}</p><small>${esc(f.strength)} · ${f.samples} 个请求样本${f.hard?" · 触发硬红线":""}</small>
    <div class="metric-details" data-metrics="${f.id}"></div><div>${ids(f.evidence)}</div></details>`).join("")}</article>`;
}

function metricContent(f) {
  const tables = Object.entries(f.metrics).filter(([,v])=>Array.isArray(v) && v.length && v.every(a=>a && typeof a==="object" && !Array.isArray(a)));
  const details = { ...f.metrics };
  let html = "";
  for (const [key,data] of tables) {
    const cols = [...new Set(data.flatMap(Object.keys))];
    html += `<div class="tablewrap"><table><caption>${esc(key)}</caption><thead><tr>${attrs(cols)}</tr></thead><tbody>${
      data.map(row=>`<tr>${cols.map(k=>`<td>${esc(typeof row[k]==="object" && row[k]!==null ? JSON.stringify(row[k]) : row[k] ?? "未返回")}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
    delete details[key];
  }
  return html+(Object.keys(details).length ? raw(details) : "");
}

function requestTable(r) {
  const names=new Map(r.findings.map(f=>[f.id,f.name]));
  const cols=["编号 / 探针","协议 / 伪装","HTTP","耗时 s","TTFT ms","返回模型","输入","输出","缓存","推理","本地期望","差额"];
  return `<details class="card reportsection" id="allRequests"><summary><strong>全量请求明细 · ${r.requests.length} 次</strong></summary>
    <div class="tablewrap"><table><thead><tr>${attrs(cols)}</tr></thead><tbody>${r.requests.map(x=> {
      const fields=[`${x.protocol} / ${x.disguised?"是":"否"}`,x.status ?? "未返回",num(x.elapsed,3),x.ttft==null?"未返回":num(x.ttft*1000,1),
        x.model ?? "未返回",...["input","output","cached","reasoning"].map(k=>num(x.counts[k],0)),num(x.local_input,0),num(x.input_delta,0)];
      return `<tr id="row-${x.seq}"><td><button class="seqjump" data-seq="${x.seq}">#${x.seq} ${esc(names.get(x.probe)||"协议预检")}</button></td>${
        fields.map(v=>`<td>${esc(v)}</td>`).join("")}</tr><tr id="detail-${x.seq}" hidden><td colspan="12"></td></tr>`;
    }).join("")}</tbody></table></div></details>`;
}

function openRequest(r,n,fromTable) {
  const row=r.requests.find(x=>x.seq===n), node=$(`detail-${n}`);
  if (!row || !node) return;
  $("allRequests").open=true;
  if (fromTable && !node.hidden) { node.hidden=true; return; }
  node.hidden=false;
  const cell=node.firstElementChild;
  if (!cell.hasChildNodes()) cell.innerHTML=`<h3>${esc(row.label)}</h3><small>${esc(row.method)} ${esc(row.path)} · ${esc(row.error||row.finish||"未返回")}</small>`+
    [["脱敏请求头",row.headers],["请求参数与原文提问",row.body],["响应头",row.response_headers],["原文回答",row.text],
     ["完整原始 usage",row.usage??"未返回"],["响应片段",row.snippet],["调用与输出项",{calls:row.calls,output:row.output_items}],
     ["阶段与流式时间序列",{phases:row.phases,events:row.events,chunks:row.chunks}]]
    .map(([k,v])=>`<details class="fold"><summary>${k}</summary>${raw(v)}</details>`).join("");
  if (!fromTable) $(`row-${n}`).scrollIntoView({block:"start"});
}

export function renderReport(retest) {
  const root=$("reportView");
  if (!state.report) {
    root.innerHTML='<div class="empty">完成一轮检测后，可在此查看评分、费用与原始样本。<br><a href="#work">前往探针工作台 →</a></div>';
    return;
  }
  const r=shown(), h=r.head, m=r.meta, v=r.verdict, l=m.ledger || {};
  const lookup = i=>r.findings.find(x=>x.id===i)?.summary || "本轮未测";
  const abnormal = r.findings.filter(f=>["需关注","异常","证据不足"].includes(f.status)).map(f=>f.id);
  const jump = f=>`<a href="#finding-${f.id}" data-find="${f.id}">#${f.id} ${esc(f.name)}</a>`;
  root.innerHTML=`<div class="toolbar">${[["json","JSON"],["csv","CSV 明细"],["md","Markdown"],["png","高清 PNG"]].map(([k,v])=>`<button data-format="${k}">导出 ${v}</button>`).join("")}
    <button id="retest" ${abnormal.length?"":"disabled"}>仅复测异常项（${abnormal.length}）</button></div>
    ${m.stop?`<p class="notice">${esc(m.stop)}</p>`:""}${m.history_summary?'<p class="notice">本地历史摘要，长请求与时间序列可能经过截断。</p>':""}
    <div class="reporttop"><article class="card"><div class="cardhead"><h2>${esc(m.name)}</h2>${badge(h.health)}</div>
    <div class="scoreline"><div class="score" style="--score:${Math.max(0,Math.min(100,Number(h.score)||0))}"><b>${h.score==null?"—":num(h.score,1)}</b></div>
    <div><h3>能力评分 / 100</h3><p class="hint">已测 ${h.score_coverage}/5 项 · 权重 ${esc(m.controls?.weights?.join(" / ")||"未返回")}</p>
    <b>${esc(v.label)}</b></div></div><p>${esc(h.summary)}</p><p class="hint">${esc(date(m.start))} · ${esc(m.period)}<br>${esc(m.model)} · ${esc(m.base_url)}<br>${esc(m.route)}<br>
    ${m.prices?"费用估算 "+money(r.totals.cost):"未配置官方单价，已跳过计算"}${r.totals.unknown_cost?` · ${r.totals.unknown_cost} 条费用未知`:""}<br>随机盐 ${esc(m.salt)}</p></article>
    <article class="card">${groups.slice(0,2).map(([lo,hi,title])=>`<h3>${title}</h3><div class="minilinks">${r.findings.filter(f=>f.id>=lo&&f.id<=hi).map(jump).join("") || "本轮未选"}</div>`).join("")}
    <h3>健康灯触发项</h3><div class="minilinks">${r.findings.filter(f=>h.triggers?.includes(f.id)).map(jump).join("")||"无已记录触发项"}</div></article></div>
    <div class="kpis">${metric("实际有效倍率",multiplier(r),m.prices?"同轮实扣 / 已配置价格的理论费用":"未配置官方单价，已跳过计算")}
    ${metric("实测缓存率",pct(h.cache_rate),`${lookup(7)} · ${lookup(18)}`)}${metric("输入计数真实性",r.findings.find(f=>f.id===11)?.status||"未测",
    `${h.input_verdict} · 注入差额 ${num(h.injection,0)} tok`)}</div>
    <details class="card"><summary>补填测后余额，重算实际有效倍率</summary><div class="fourcol">
    <label>额度类型<select id="postKind"><option value="balance">剩余余额</option><option value="used">累计已用</option></select></label>
    <label>测前额度<input id="postBefore" type="number" min="0" step="any" value="${esc(l.before??"")}"></label>
    <label>测后额度<input id="postAfter" type="number" min="0" step="any" value="${esc(l.after??"")}"></label>
    <label>每美元单位<input id="postUnits" type="number" min="0" step="any" value="${esc(l.units_per_usd??1)}"></label></div><output id="recalculated">${esc(multiplier(r))}</output></details>
    ${groups.map(([lo,hi,title])=>sectionFindings(r,lo,hi,title)).join("")}
    <article class="card reportsection"><h2>${esc(v.label)}</h2><p>${esc(v.summary)}</p><ol>${v.reasons.map(e=>`<li><a href="#finding-${e.id}" data-find="${e.id}">#${e.id} ${esc(e.text)}</a></li>`).join("")}</ol>
    ${v.guidance.map((x,i)=>`<p class="hint">${["首充","适合","不适合","复测"][i]} · ${esc(x)}</p>`).join("")}</article>
    <div class="tablewrap"><div class="six">${sixValues(r).map(([k,v])=>metric(k,v)).join("")}</div></div>${requestTable(r)}
    <details class="card reportsection"><summary>待确认清单</summary><ul>${r.pending.map(x=>`<li>${esc(x)}</li>`).join("")}</ul></details>`;
  $("postKind").value=l.kind || "balance";
  const inputValue = id=>$(id).value===""?null:Number($(id).value);
  for (const id of ["postBefore","postAfter","postKind","postUnits"]) {
    $(id).oninput=()=>{
      recalculate(state.report,inputValue("postBefore"),inputValue("postAfter"),$("postKind").value,inputValue("postUnits"));
      $("recalculated").textContent=multiplier(state.report);
      root.querySelector(".kpis strong").textContent=multiplier(state.report);
    };
    $(id).onchange=()=>{ try { archive(state.report); } catch { toast("本地空间已满，本轮报告仍可导出。"); } };
  }
  root.querySelectorAll("[data-find]").forEach(a=>a.onclick=e=>{
    e.preventDefault();
    const node=$("finding-"+a.dataset.find);
    if(node){node.open=true;node.scrollIntoView({block:"center"});}
  });
  root.querySelectorAll(".finding").forEach(node=>node.ontoggle=()=>{
    const panel=node.querySelector("[data-metrics]");
    if (node.open && !panel.hasChildNodes()) {
      const f=shown().findings.find(x=>x.id===Number(panel.dataset.metrics));
      panel.innerHTML=metricContent(f);
    }
  });
  root.querySelectorAll("[data-seq]").forEach(b=>b.onclick=()=>openRequest(r,Number(b.dataset.seq),!!b.closest("#allRequests")));
  root.querySelectorAll("[data-format]").forEach(b=>b.onclick=()=>exportReport(shown(),b.dataset.format).catch(e=>toast(e.message)));
  $("retest").onclick=()=>retest(abnormal);
}

export function renderComparison() {
  const rows=state.history.filter(r=>state.comparison.has(r.run_id)).map(r=>visible(r,$("privacy").checked));
  $("comparison").innerHTML=rows.length?`<div class="tablewrap"><table><thead><tr>${attrs(["指标",...rows.map(r=>r.meta.name)])}</tr></thead><tbody>${
    [["模型",r=>r.meta.model],["时段",r=>r.meta.period],["能力分",r=>num(r.head.score,1)],["健康灯",r=>r.head.health],
     ["实测缓存率",r=>pct(r.head.cache_rate)],["注入量 / tok",r=>num(r.head.injection,0)],["实际倍率",multiplier],["裁决",r=>r.verdict.label]]
    .map(([name,fn])=>`<tr><th>${name}</th>${rows.map(r=>`<td>${esc(fn(r))}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`:
    '<p class="hint">在上方选择需要对比的报告。</p>';
}
