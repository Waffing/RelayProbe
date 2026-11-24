import { money, num, pct } from "./state.js";

export function saveFile(name, content, type = "application/json") {
  const url = URL.createObjectURL(content instanceof Blob ? content : new Blob([content], { type }));
  const link = document.createElement("a");
  link.download = name; link.href = url; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

export function sixValues(r) {
  const t = r.totals;
  return [["首字延迟", t.ttft == null ? "未返回" : num(t.ttft*1000,0)+" ms"],
    ["输出速度", t.output_tps == null ? "未返回" : num(t.output_tps,1)+" tok/s"],
    ["请求 / 失败", `${t.requests} / ${t.failed}`], ["输入 tokens",num(t.input,0)],
    ["输出 tokens",num(t.output,0)],["缓存读取",num(t.cached,0)]];
}

function csvCell(value) {
  let text = typeof value === "object" && value !== null ? JSON.stringify(value) : String(value ?? "");
  if (/^[=+@\t\r-]/.test(text)) text = "'"+text;
  return '"'+text.replaceAll('"','""')+'"';
}
export function csv(r) {
  const names = new Map(r.findings.map(f => [f.id,f.name]));
  const cols = ["seq","probe","probe_name","label","protocol","disguised","method","path","status","elapsed","ttft","model",
    "input","output","cached","reasoning","local_input","input_delta","local_output","cost","finish","error","headers",
    "body","response_headers","text","usage","snippet","events","chunks","calls","phases","output_items"];
  return "\ufeff"+[cols, ...r.requests.map(x => {
    const row = {...x,...x.counts,probe_name:names.get(x.probe) || "协议预检"};
    return cols.map(k => row[k]);
  })].map(cells => cells.map(csvCell).join(",")).join("\r\n");
}
const md = text => String(text ?? "").replace(/[\\`*_<>[\]|#]/g,"\\$&").replace(/\r?\n/g," ");
export function markdown(r) {
  const m = r.meta, h = r.head, v = r.verdict;
  return [`# ${md(m.name)} · 渠道评测`, "", `${md(m.start)} · ${md(m.period)} · ${md(m.model)}`, "",
    `${md(m.route)} · ${md(m.base_url)}`, "", m.stop ? `**${md(m.stop)}**` : "",
    `能力分 ${num(h.score)}（${h.score_coverage}/5） · 健康灯 ${md(h.health)} · ${md(v.label)}`, "",
    `有效倍率 ${num(h.effective_multiplier,4)} · 实测缓存率 ${pct(h.cache_rate)} · 官方口径估算 ${money(r.totals.cost)}`,
    "", md(h.input_verdict), "", "## 观测汇总", "", ...sixValues(r).map(([k,v])=>`- ${k} ${v}`),
    "", "## 检测证据", "", ...r.findings.flatMap(f=>[`### #${f.id} ${md(f.name)}`, "",
      `${md(f.status)} · ${md(f.strength)} · ${f.samples} 个样本`, "", md(f.summary), "",
      `请求编号 ${f.evidence.map(n=>"#"+n).join("、") || "无"}`, ""]),
    "## 裁决", "", md(v.label), "", md(v.summary), ...v.reasons.map(x=>`- #${x.id} ${md(x.text)}`),
    ...v.guidance.map((x,i)=>`- ${["首充","适合","不适合","复测"][i]} · ${md(x)}`), "", "## 待确认", "",
    ...r.pending.map(x=>`- ${md(x)}`), "", `本轮随机盐 \`${md(m.salt)}\``].join("\n");
}

export async function png(r) {
  const width = 1040, scale = 2, pad = 62;
  const lines = [];
  const draft = document.createElement("canvas").getContext("2d");
  const font = (size, weight) => `${weight} ${size}px "Microsoft YaHei", "PingFang SC", sans-serif`;
  function line(text, size = 23, color = "#d7e4ee", weight = 450, space = 10) {
    draft.font = font(size, weight);
    let part = "";
    for (const ch of String(text)) {
      if (draft.measureText(part+ch).width > width-2*pad) {
        lines.push({part,size,color,weight,space:3}); part = "";
      }
      part += ch;
    }
    lines.push({part,size,color,weight,space});
  }
  line("RELAY PROBE  /  渠道测评",22,"#77d8c6",650,22);
  line(r.meta.name,48,"#f2f6fa",700,12);
  line(`${r.meta.model}   ·   ${r.meta.period}   ·   ${r.meta.start}`,20,"#abc1d1");
  line(`${r.meta.route}   ·   ${r.meta.base_url}`,19,"#abc1d1",450,25);
  if (r.meta.stop) line(r.meta.stop,23,"#ffc790");
  line(`能力分 ${num(r.head.score)}   ·   健康灯 ${r.head.health}   ·   ${r.verdict.label}`,34,"#85dfcd",650,18);
  line(`有效倍率 ${num(r.head.effective_multiplier,4)}    实测缓存率 ${pct(r.head.cache_rate)}    花费 ${money(r.totals.cost)}`);
  line(r.head.input_verdict,21,"#abc1d1",450,20);
  line(r.verdict.summary,24);
  for (const e of r.verdict.reasons) line(`#${e.id}   ${e.text}（${e.samples} 个样本）`,20,"#bad0de");
  line("运行数据",27,"#f6c294",650,16);
  for (const [k,v] of sixValues(r)) line(`${k}     ${v}`,24);
  line(`能力覆盖 ${r.head.score_coverage}/5   ·   盐值 ${r.meta.salt}`,17,"#98adbd");
  const height = 2*pad+lines.reduce((h,x)=>h+x.size*1.45+x.space,0);
  const canvas = document.createElement("canvas");
  canvas.width=width*scale; canvas.height=Math.ceil(height)*scale;
  const ctx = canvas.getContext("2d"); ctx.scale(scale,scale);
  const grad = ctx.createLinearGradient(0,0,width,height);
  grad.addColorStop(0,"#132c38"); grad.addColorStop(.4,"#182330"); grad.addColorStop(1,"#101824");
  ctx.fillStyle=grad; ctx.fillRect(0,0,width,height);
  ctx.fillStyle="#67d8c4"; ctx.fillRect(0,0,width,7);
  let y = pad;
  for (const x of lines) {
    ctx.fillStyle=x.color; ctx.font=font(x.size,x.weight); ctx.textBaseline="top";
    ctx.fillText(x.part,pad,y); y+=x.size*1.45+x.space;
  }
  const blob = await new Promise(resolve=>canvas.toBlob(resolve,"image/png"));
  if (!blob) throw new Error("无法生成 PNG");
  return blob;
}

export async function exportReport(r, format) {
  const name = `relay-probe-${r.run_id.slice(0,12)}.${format}`;
  if (format === "json") saveFile(name,JSON.stringify(r,null,2));
  if (format === "csv") saveFile(name,csv(r),"text/csv;charset=utf-8");
  if (format === "md") saveFile(name,markdown(r),"text/markdown;charset=utf-8");
  if (format === "png") saveFile(name,await png(r));
}
