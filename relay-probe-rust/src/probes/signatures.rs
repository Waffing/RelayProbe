use super::{mean, percentile, question, ratio, Probe};
use crate::{core::protocols::Options, schemas::Finding};
use serde_json::{json, Value};
pub async fn execute(c: &Probe<'_>) -> Result<Finding, String> {
    if c.id == 22 {
        let (value, rows) = if let Some(f) = c.result(6) {
            (
                f.metrics["profile_delta"].as_i64(),
                c.traffic()
                    .into_iter()
                    .filter(|r| f.evidence.contains(&r.seq))
                    .collect(),
            )
        } else {
            let r = c
                .ask(
                    "注入指纹基线",
                    format!("样本 {}，只回复 OK。", c.run.salt),
                    Options {
                        bare: Some(false),
                        ..Default::default()
                    },
                )
                .await?;
            (r.input_delta, vec![r])
        };
        let metrics = json!({"observed":value,"library":c.run.spec.fingerprints,"provenance":"初始 4233 / 4157 来自规格所述 2026-11 三家实测，未经独立核实"});
        let Some(v) = value else {
            return Ok(c.lack("无有效输入差额", metrics, Some(&rows)));
        };
        let hit = c.run.spec.fingerprints.contains(&v);
        Ok(c.finding(
            format!(
                "输入差额 {v} tok，{}库中数值",
                if hit { "匹配" } else { "未匹配" }
            ),
            metrics,
            Some(&rows),
            if hit { "需关注" } else { "通过" },
            None,
            false,
        ))
    } else {
        let (prompt, _) = question(&c.run.salt, 2);
        let text = format!("回执 {}。{prompt}", c.run.salt);
        let opts = Options {
            key: Some("answer".into()),
            ..Default::default()
        };
        let a = c.ask("同题首轮", text.clone(), opts.clone()).await?;
        c.run.wait(1.).await?;
        let b = c.ask("间隔重发", text, opts).await?;
        let rel = ratio(b.ttft, a.ttft);
        let identical = a.text == b.text;
        if !a.ok() || !b.ok() || rel.is_none() {
            return Ok(c.lack("同题样本不完整", json!({}), None));
        }
        let rel = rel.unwrap();
        let suspect = identical && rel < c.rule("answer_ttft_ratio");
        Ok(c.finding(
            format!(
                "两次回答{}，第二次 TTFT 为首次的 {rel:.2} 倍{}",
                if identical { "相同" } else { "不同" },
                if suspect {
                    "，疑似命中站内答案缓存"
                } else {
                    ""
                }
            ),
            json!({"ttft_ratio":rel,"identical":identical}),
            None,
            if suspect { "需关注" } else { "通过" },
            None,
            false,
        ))
    }
}
pub fn passive(c: &Probe<'_>) -> Finding {
    match c.id {
        21 => usage_rewrite(c),
        23 => drift(c),
        24 => mixed(c),
        25 => bursts(c),
        27 => {
            let rows = c.traffic();
            let observable:Vec<_>=rows.iter().map(|r|json!({"seq":r.seq,"model":r.model,"fingerprint":r.fingerprint,"status":r.status,"ttft":r.ttft})).collect();
            c.finding(
                "待对照确切指纹",
                json!({"observable":observable}),
                Some(&rows),
                "待对照确切指纹",
                None,
                false,
            )
        }
        _ => unreachable!(),
    }
}
fn usage_rewrite(c: &Probe<'_>) -> Finding {
    let rows: Vec<_> = c
        .traffic()
        .into_iter()
        .filter(|r| r.status == Some(200))
        .collect();
    let mut issues = vec![];
    let mut missing = vec![];
    for r in &rows {
        let mut bad = vec![];
        if let (Some(i), Some(o), Some(t)) = (r.n("input"), r.n("output"), r.n("total")) {
            if t != i + o {
                bad.push("总量不守恒");
            }
        }
        if r.n("cached").zip(r.n("input")).is_some_and(|(a, b)| a > b) {
            bad.push("缓存大于输入");
        }
        if r.n("cached")
            .is_some_and(|v| v > 0 && (v % 128 != 0 || v < 1024))
        {
            bad.push("缓存粒度或门槛不符");
        }
        if r.calls.is_empty()
            && r.n("output").zip(r.n("reasoning")).is_some_and(|(o, re)| {
                ((o - re - r.local_output as i64).abs() as f64) > c.rule("output_tolerance")
            })
        {
            bad.push("可见输出交叉差幅");
        }
        if !bad.is_empty() {
            issues.push(json!({"seq":r.seq,"observations":bad}));
        }
        let mut absent = vec![];
        for (key, has) in [
            ("system_fingerprint", r.fingerprint.is_some()),
            (
                "x-request-id",
                r.response_headers.get("x-request-id").is_some(),
            ),
            ("cached_tokens", r.n("cached").is_some()),
            ("reasoning_tokens", r.n("reasoning").is_some()),
            ("usage", r.usage.is_some()),
        ] {
            if !has {
                absent.push(key);
            }
        }
        if !absent.is_empty() {
            missing.push(json!({"seq":r.seq,"missing":absent}));
        }
    }
    if rows.is_empty() {
        return c.lack("无成功的协议响应", json!({}), Some(&rows));
    }
    c.finding(
        format!(
            "{} 条响应中 {} 条计数异常，{} 条缺少参考字段",
            rows.len(),
            issues.len(),
            missing.len()
        ),
        json!({"issues":issues,"missing":missing,"scope":"字段缺失单列，无法据此归因改写层"}),
        Some(&rows),
        if issues.is_empty() && missing.is_empty() {
            "通过"
        } else {
            "需关注"
        },
        None,
        false,
    )
}
fn drift(c: &Probe<'_>) -> Finding {
    let rows: Vec<_> = c
        .traffic()
        .into_iter()
        .filter(|r| r.model.is_some() || r.fingerprint.is_some())
        .collect();
    let mut models = std::collections::BTreeMap::new();
    let mut fps = std::collections::BTreeMap::new();
    for r in &rows {
        if let Some(m) = &r.model {
            *models.entry(m.clone()).or_insert(0) += 1;
        }
        if let Some(f) = &r.fingerprint {
            *fps.entry(f.clone()).or_insert(0) += 1;
        }
    }
    if models.is_empty() {
        return c.lack("响应未返回模型", json!({}), Some(&rows));
    }
    let re = regex::Regex::new(r"(?:-(?:\d{4}-\d{2}-\d{2}|\d{8}|\d{4}|latest|preview|snapshot))+$")
        .unwrap();
    let family = |s: &str| {
        re.replace_all(
            &s.to_lowercase()
                .rsplit('/')
                .next()
                .unwrap_or("")
                .to_string(),
            "",
        )
        .into_owned()
    };
    let requested = &c.run.spec.model;
    let mismatches: Vec<_> = models.keys().filter(|m| *m != requested).cloned().collect();
    let alias = ["auto", "default", "router", "latest"].contains(&family(requested).as_str());
    let foreign: Vec<_> = mismatches
        .iter()
        .filter(|m| !alias && family(m) != family(requested))
        .cloned()
        .collect();
    c.finding(format!("{} 个返回模型名，{} 种指纹，{} 个异构返回名",models.len(),fps.len(),foreign.len()),
        json!({"models":models,"fingerprints":fps,"unexpected_names":mismatches,"heterogeneous":foreign,"scope":"审计响应自报标识；同族日期快照和指纹跳变仅提示复核"}),
        Some(&rows),if !foreign.is_empty(){"异常"}else if !mismatches.is_empty()||fps.len()>1{"需关注"}else{"通过"},None,!foreign.is_empty())
}
pub async fn checkpoint(c: &Probe<'_>, phase: &str) -> Result<(), String> {
    let (prompt, _) = question(&c.run.salt, 0);
    let a = c
        .ask(
            &format!("{phase} · 短分词"),
            format!("回执 {} | 短句 72，café 🧭，请回复 OK。", c.run.salt),
            Options::default(),
        )
        .await?;
    let b = c
        .ask(
            &format!("{phase} · 短推理"),
            prompt,
            Options {
                effort: Some("low".into()),
                ..Default::default()
            },
        )
        .await?;
    let mut headers = json!({});
    for k in [
        "server",
        "via",
        "x-upstream",
        "x-served-by",
        "openai-processing-ms",
    ] {
        if let Some(v) = b.response_headers.get(k) {
            headers[k] = v.clone();
        }
    }
    let mut checkpoints = c
        .memo("checkpoints")
        .as_array()
        .cloned()
        .unwrap_or_default();
    checkpoints.push(json!({"phase":phase,"seqs":[a.seq,b.seq],"latency":mean([Some(a.elapsed),Some(b.elapsed)]),
        "fingerprint_delta":a.input_delta,"reasoning":b.n("reasoning"),"headers":headers,
        "id_prefix":b.response_id.as_deref().unwrap_or("").split(['_','-']).next(),"fingerprint":b.fingerprint}));
    c.set("checkpoints", json!(checkpoints));
    Ok(())
}
fn mixed(c: &Probe<'_>) -> Finding {
    let samples = c
        .memo("checkpoints")
        .as_array()
        .cloned()
        .unwrap_or_default();
    if samples.len() < 3 {
        return c.lack(
            format!("开头、中段、末尾取得 {}/3 组", samples.len()),
            json!({"phases":samples}),
            None,
        );
    }
    let identities: std::collections::HashSet<_> = samples
        .iter()
        .map(|s| {
            json!([
                s["headers"]["x-upstream"],
                s["headers"]["server"],
                s["id_prefix"],
                s["fingerprint"],
                s["fingerprint_delta"],
                s["reasoning"]
            ])
            .to_string()
        })
        .collect();
    let mut sorted = samples.clone();
    sorted.sort_by(|a, b| {
        a["latency"]
            .as_f64()
            .unwrap_or(0.)
            .total_cmp(&b["latency"].as_f64().unwrap_or(0.))
    });
    let mut groups: Vec<Value> = vec![];
    for s in &sorted {
        if groups.last().is_none_or(|g| {
            s["latency"].as_f64().unwrap_or(0.)
                > g["min_s"].as_f64().unwrap_or(0.) * c.rule("duration_ratio")
        }) {
            groups.push(json!({"min_s":s["latency"],"phases":[]}));
        }
        groups.last_mut().unwrap()["phases"]
            .as_array_mut()
            .unwrap()
            .push(s["phase"].clone());
    }
    c.finding(
        format!("3 个时点出现 {} 组可观察特征", identities.len()),
        json!({"phases":samples,"latency_groups":groups,"feature_groups":identities.len(),
        "latency_range":[sorted.first().unwrap()["latency"],sorted.last().unwrap()["latency"]]}),
        None,
        if identities.len() > 1 {
            "需关注"
        } else {
            "通过"
        },
        None,
        false,
    )
}
fn bursts(c: &Probe<'_>) -> Finding {
    let rows: Vec<_> = c
        .traffic()
        .into_iter()
        .filter(|r| !r.chunks.is_empty())
        .collect();
    if rows.is_empty() {
        return c.lack("没有输出 chunk 时间序列", json!({}), Some(&rows));
    }
    let mut stats = vec![];
    let mut flagged = vec![];
    for r in &rows {
        let times: Vec<_> = r.chunks.iter().map(|c| c["t"].as_f64().unwrap()).collect();
        let mut gaps = vec![times[0]];
        gaps.extend(times.windows(2).map(|w| w[1] - w[0]));
        let span = times.last().unwrap() - times[0];
        stats.push(json!({"seq":r.seq,"max_silence":gaps.iter().copied().fold(0.,f64::max),"chunks":times.len(),
            "gap_p50":percentile(gaps.iter().copied(),0.5),"gap_p95":percentile(gaps.iter().copied(),0.95),"arrival_span":span}));
        if times[0] >= c.rule("burst_gap_s")
            && span < c.rule("burst_gap_s") / 10.
            && times.len() >= 2
        {
            flagged.push(r.seq);
        }
    }
    c.finding(
        format!(
            "{} 条流式样本中 {} 条出现静默后集中输出",
            rows.len(),
            flagged.len()
        ),
        json!({"distributions":stats,"flagged":flagged}),
        Some(&rows),
        if flagged.is_empty() {
            "通过"
        } else {
            "需关注"
        },
        None,
        false,
    )
}
