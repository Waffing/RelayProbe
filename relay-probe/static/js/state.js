const PREFIX = "relay-probe.v1.";
const allowed = new Set(["history", "prices", "preferences", "theme", "privacy"]);
const sensitive = /authorization|api[-_]?key|cookie|password|credential|secret|access[-_]?token|refresh[-_]?token|auth[-_]?token|signature/i;
export const state = { report: null, history: [], prices: {}, config: null, profiles: [], selected: new Set(),
  mode: "quick", run: null, preferences: {}, comparison: new Set() };

export function read(name, fallback) {
  try { return JSON.parse(localStorage.getItem(PREFIX + name)) ?? fallback; }
  catch { return fallback; }
}
export function write(name, value) {
  if (!allowed.has(name)) throw new Error("未知的本地保存项目");
  localStorage.setItem(PREFIX + name, JSON.stringify(clean(value)));
}

export function clean(value, hide = []) {
  if (typeof value === "string") {
    for (const token of hide) {
      if (token) value = value.replaceAll(token, "[已隐藏]");
    }
    return value.replace(/\b(?:sk|rk|sess)-[a-z0-9_-]{6,}/gi, "[已脱敏]")
      .replace(/\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, "[已脱敏]")
      .replace(/([?&](?:key|api[_-]?key|token|auth|signature)=)[^&\s"']+/gi, "$1[已脱敏]");
  }
  if (Array.isArray(value)) return value.map(v => clean(v, hide));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value)
    .filter(([k]) => !sensitive.test(k) && !["__proto__", "constructor", "prototype"].includes(k))
    .map(([k,v]) => [clean(k, hide), clean(v, hide)]));
  return value;
}

export function visible(report, privacy) {
  if (!privacy) return clean(report);
  let host = "";
  try { host = new URL(report.meta.base_url).hostname; } catch { /* A redacted imported report has no hostname. */ }
  const hide = [report.meta.base_url, host, host.replace(/^\[|\]$/g, "")].filter(s => s && s !== "[已隐藏]");
  const result = clean(report, hide);
  result.meta.base_url = "[已隐藏]";
  return result;
}

export function isReport(r) {
  const probe = n => Number.isInteger(n) && n>=1 && n<=40;
  return r?.version === 1 && typeof r.run_id === "string" && r.meta && r.head && r.totals && r.verdict
    && ["name","base_url","model","salt","mode","start"].every(k=>typeof r.meta[k]==="string")
    && Number.isInteger(r.head.score_coverage) && Number.isInteger(r.totals.requests)
    && (r.totals.unknown_cost == null || Number.isInteger(r.totals.unknown_cost))
    && Array.isArray(r.findings) && Array.isArray(r.requests) && Array.isArray(r.pending)
    && Array.isArray(r.verdict.reasons) && Array.isArray(r.verdict.guidance)
    && r.verdict.reasons.every(e=>e && probe(e.id) && typeof e.text==="string")
    && r.findings.every(f => f && probe(f.id) && Number.isInteger(f.samples) && Array.isArray(f.evidence) && f.metrics)
    && r.requests.every(x => Number.isInteger(x.seq) && x.counts);
}

function shortened(value, cap = 1400) {
  if (typeof value === "string" && value.length > cap) return `${value.slice(0,cap)}… [历史截断，原长 ${value.length}]`;
  if (Array.isArray(value)) return value.map(x => shortened(x, cap));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k,v]) => [k, shortened(v, cap)]));
  return value;
}

export function archive(r) {
  const stored = shortened(clean(r));
  for (const row of stored.requests) {
    for (const k of ["body","output_items","response_headers","headers"]) {
      const serialized = JSON.stringify(row[k]);
      if (serialized?.length > 3000) {
        row[k] = {history_excerpt:serialized.slice(0,1800),history_note:"长字段已截断，完整原文请查看本轮 JSON 导出。"};
      }
    }
    for (const k of ["chunks","events"]) {
      if (row[k]?.length > 64) { row[k+"_original_count"] = row[k].length; row[k] = row[k].slice(0,64); }
    }
  }
  stored.meta.history_summary = true;
  const updated = [stored, ...state.history.filter(x => x.run_id !== stored.run_id)];
  write("history", updated);
  state.history = updated;
}

export const num = (v, digits = 2) => v == null || !Number.isFinite(v) ? "未返回" :
  v.toLocaleString("zh-CN", { maximumFractionDigits: digits });
export const pct = v => v == null ? "未测" : `${num(v*100,1)}%`;
export const money = v => v == null ? "未配置" : `$${num(v,8)}`;
export const esc = v => String(v ?? "").replace(/[&<>"']/g, ch => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]));
export const $ = id => document.getElementById(id);
let toastTimer;
export function toast(text) {
  $("toast").textContent = text;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { $("toast").textContent = ""; }, 5500);
}
