use crate::{
    core::runner::Run,
    probes::{mean, ratio},
};
use chrono::{DateTime, Local, Timelike};
use serde_json::{json, Value};

pub fn report(run: &Run) -> Value {
    let d = run.data.lock().unwrap();
    let mut rows = d.rows.clone();
    rows.sort_by_key(|r| r.seq);
    let findings: Vec<_> = d.findings.values().cloned().collect();
    let metric = |id: usize, key: &str| {
        d.findings
            .get(&id)
            .map(|f| f.metrics[key].clone())
            .unwrap_or(Value::Null)
    };
    let graded: Vec<_> = findings
        .iter()
        .filter(|f| (1..=5).contains(&f.id) && f.score.is_some())
        .collect();
    let weights = &run.spec.controls.weights;
    let weighted = graded.iter().map(|f| weights[f.id - 1]).sum::<f64>();
    let score = if weighted > 0. {
        Some(
            (1000.
                * graded
                    .iter()
                    .map(|f| f.score.unwrap() * weights[f.id - 1])
                    .sum::<f64>()
                / weighted)
                .round()
                / 10.,
        )
    } else {
        None
    };
    let alerts: Vec<_> = findings
        .iter()
        .filter(|f| ["需关注", "异常"].contains(&f.status.as_str()))
        .collect();
    let hard: Vec<_> = alerts
        .iter()
        .filter(|f| f.hard && f.strength == "实测检出" && [1, 7, 11, 17, 18, 23].contains(&f.id))
        .collect();
    let complete: Vec<_> = rows
        .iter()
        .filter(|r| r.method == "POST" && r.ok())
        .collect();
    let partial = !d.stop.is_empty() || findings.iter().any(|f| f.status == "证据不足");
    let severe = alerts
        .iter()
        .any(|f| f.status == "异常" && [2, 7, 11, 17, 23, 28, 37, 38].contains(&f.id));
    let high_injection =
        metric(6, "profile_delta").as_f64().unwrap_or(0.) >= run.spec.rule("high_injection");
    let health = if !hard.is_empty() || severe || high_injection {
        "红"
    } else if !alerts.is_empty() || partial || complete.is_empty() {
        "黄"
    } else {
        "绿"
    };
    let grade = if !hard.is_empty() {
        Some("D")
    } else if score.is_none() || complete.is_empty() {
        None
    } else if health == "红" {
        Some(if score.unwrap() >= run.spec.rule("score_c") {
            "C"
        } else {
            "D"
        })
    } else if score.unwrap() >= run.spec.rule("score_a")
        && health == "绿"
        && graded.len() == 5
        && !partial
    {
        Some("A")
    } else if score.unwrap() >= run.spec.rule("score_b") {
        Some("B")
    } else if score.unwrap() >= run.spec.rule("score_c") {
        Some("C")
    } else {
        Some("D")
    };
    let mut ordered: Vec<_> = findings.iter().filter(|f| f.samples > 0).collect();
    ordered.sort_by_key(|f| (!f.hard, f.status != "异常", f.status != "需关注", f.id));
    let reasons: Vec<_> = ordered
        .iter()
        .take(5)
        .map(|f| json!({"id":f.id,"text":f.summary,"samples":f.samples,"evidence":f.evidence}))
        .collect();
    let mut totals = d.budget.snapshot();
    let model_rows: Vec<_> = rows.iter().filter(|r| r.method == "POST").collect();
    for key in ["input", "output", "cached", "reasoning"] {
        let known: Vec<_> = model_rows.iter().filter_map(|r| r.n(key)).collect();
        totals[key] = json!(if known.is_empty() {
            None
        } else {
            Some(known.iter().sum::<i64>())
        });
        totals[format!("{key}_reported")] = json!(known.len());
    }
    let stream_time = model_rows
        .iter()
        .filter(|r| r.chunks.len() > 1)
        .map(|r| {
            r.chunks.last().unwrap()["t"].as_f64().unwrap() - r.chunks[0]["t"].as_f64().unwrap()
        })
        .sum::<f64>();
    let stream_tokens = model_rows
        .iter()
        .filter(|r| r.chunks.len() > 1)
        .map(|r| {
            r.chunks[1..]
                .iter()
                .filter_map(|c| c["tokens"].as_f64())
                .sum::<f64>()
        })
        .sum::<f64>();
    let failed = rows.iter().filter(|r| !r.ok()).count();
    totals["requests"] = json!(rows.len());
    totals["failed"] = json!(failed);
    totals["ttft"] = json!(mean(complete.iter().map(|r| r.ttft)));
    totals["output_tps"] = json!(ratio(Some(stream_tokens), Some(stream_time)));
    let start = DateTime::parse_from_rfc3339(&run.started).unwrap();
    let period = if start.hour() >= 19 {
        "晚高峰 19:00–23:59"
    } else if start.hour() < 7 {
        "凌晨低峰"
    } else {
        "白天平峰"
    };
    let scope = if run.spec.bare {
        "裸请求".into()
    } else {
        format!("完整伪装 {}", run.profile.name)
    };
    let origin = if run.profile.source == "自建基准模板" {
        "自建基准"
    } else {
        &run.profile.source
    };
    let route = format!(
        "走 {} · {scope}（{origin} {} tok，与外部工具 9845 口径独立）",
        run.protocol(),
        run.profile.baseline_tokens
    );
    let summary = format!(
        "{} 次请求，{failed} 次失败，{} 项异常或需关注，{} 项触发硬红线。",
        rows.len(),
        alerts.len(),
        hard.len()
    );
    let mut pending = vec![
        "草案·待用户确认，判分分界、证据提示阈值与能力权重。".to_owned(),
        "本地基准采用 o200k_base 规范化请求内容；供应商内部序列化开销待确认。".into(),
        "BPS 确切指纹待确认。".into(),
        "4233 / 4157 源自规格所述 2026-11 三家实测，来源未独立复核。".into(),
    ];
    if run.spec.prices.is_none() {
        pending.push("未配置官方单价，已跳过计算。".into());
    }
    if graded.len() < 5 {
        pending.push(format!(
            "能力评分覆盖 {}/5 项，已测项按权重归一。",
            graded.len()
        ));
    }
    if partial {
        pending.push("样本不完整，见各项证据与运行停止原因。".into());
    }
    let mut reconciliation = d
        .findings
        .get(&15)
        .map(|f| f.metrics.clone())
        .unwrap_or(json!({}));
    let ledger = &run.spec.ledger;
    if let Some((b, a)) = ledger["before"].as_f64().zip(ledger["after"].as_f64()) {
        let amount = (a - b) * if ledger["kind"] == "used" { 1. } else { -1. }
            / ledger["units_per_usd"].as_f64().unwrap_or(1.);
        let debit = if amount >= 0. { Some(amount) } else { None };
        reconciliation["deduction_usd"] = json!(debit);
        reconciliation["effective_multiplier"] = json!(if d.budget.unknown == 0 {
            ratio(debit, totals["cost"].as_f64())
        } else {
            None
        });
    }
    let (label, guidance) = match grade {
        Some("A") => (
            "A 值得入手",
            [
                "按一次实际任务的小额预算首充",
                "本轮已通过的编程与工具场景",
                "未实测的高开销场景",
                "高峰时段或版本变更后复测",
            ],
        ),
        Some("B") => (
            "B 小额试用",
            [
                "只充值一次试用任务所需额度",
                "可复核、可重试的低成本任务",
                "无人值守的重要任务",
                "首次试用后换时段复测",
            ],
        ),
        Some("C") => (
            "C 只适合不敏感小活",
            [
                "先使用已有余额",
                "非敏感且可人工校验的小任务",
                "重要工程、长链路或高额调用",
                "异常修复后复测",
            ],
        ),
        Some("D") => (
            "D 不值得入手（避坑）",
            [
                "暂停首充",
                "验证站方修复的隔离样本",
                "付费生产工作负载",
                "拿到修复说明后复测",
            ],
        ),
        _ => (
            "证据不足，待裁决",
            ["暂缓首充", "尚待实测", "未覆盖场景", "补足计分项后复测"],
        ),
    };
    json!({"version":1,"run_id":run.id,
        "meta":{"name":run.spec.name,"base_url":run.spec.base_url,"model":run.spec.model,"mode":run.spec.mode,
            "protocol":run.protocol(),"requested_protocol":run.spec.protocol,"route":route,"profile":run.profile.name,"profile_id":run.profile.id,
            "profile_source":run.profile.source,"baseline_tokens":run.profile.baseline_tokens,"mode_bare":run.spec.bare,"start":run.started,
            "end":Local::now().to_rfc3339(),"period":period,"salt":run.salt,"selection":run.ids,"stop":d.stop,"partial":partial,
            "ledger":run.spec.ledger,"prices":run.spec.prices,"controls":run.spec.controls,"advertised_cache":run.spec.advertised_cache,"engine":concat!("Rust ", env!("CARGO_PKG_VERSION"))},
        "requests":rows,"findings":findings,"totals":totals,"pending":pending,
        "head":{"score":score,"score_coverage":graded.len(),"health":health,"triggers":alerts.iter().map(|f|f.id).collect::<Vec<_>>(),
            "effective_multiplier":reconciliation["effective_multiplier"],"deduction_usd":reconciliation["deduction_usd"],
            "cache_rate":metric(16,"mean"),"injection":metric(6,"profile_delta"),"input_verdict":d.findings.get(&11).map(|f|f.summary.as_str()).unwrap_or("未测阶梯"),"summary":summary},
        "verdict":{"grade":grade,"label":label,"hard":hard.iter().map(|f|f.id).collect::<Vec<_>>(),"reasons":reasons,"guidance":guidance,"summary":summary}})
}
