use super::billing_probes::balance_snapshot;
use super::{mean, percentile, ratio, Probe};
use crate::{
    core::{protocols::Options, tokenizer::padding},
    schemas::Finding,
};
use serde_json::json;
pub async fn execute(c: &Probe<'_>) -> Result<Finding, String> {
    match c.id {
        16 => measured(c).await,
        17 => invalidate(c).await,
        18 => ttft(c).await,
        19 => stickiness(c).await,
        _ => unreachable!(),
    }
}
async fn measured(c: &Probe<'_>) -> Result<Finding, String> {
    let prefix = padding(4096, &format!("{}-rate", c.run.salt));
    let mut rows = vec![];
    let mut segment = json!({"seqs":[]});
    for i in 0..c.run.spec.controls.cache_repeats {
        if i == 1 && c.run.ids.contains(&15) {
            segment["before"] = balance_snapshot(c, "热缓存窗口起始").await?;
        }
        let r = c
            .ask(
                &format!("固定前缀 {}", i + 1),
                prefix.clone(),
                Options {
                    key: Some("rate".into()),
                    ..Default::default()
                },
            )
            .await?;
        if i > 0 {
            segment["seqs"].as_array_mut().unwrap().push(json!(r.seq));
        }
        rows.push(r);
    }
    if c.run.ids.contains(&15) {
        segment["after"] = balance_snapshot(c, "热缓存窗口结束").await?;
        c.set("cache_ledger", segment);
    }
    let rates: Vec<_> = rows
        .iter()
        .filter(|r| r.ok())
        .filter_map(|r| r.rate())
        .collect();
    if rates.is_empty() {
        return Ok(c.lack("未返回可用缓存计数", json!({}), Some(&rows)));
    }
    let avg = mean(rates.iter().map(|v| Some(*v))).unwrap();
    let ad = c.run.spec.advertised_cache;
    Ok(c.finding(format!("含冷启动的 {} 条样本平均命中 {:.1}%",rates.len(),avg*100.),
        json!({"mean":avg,"median":percentile(rates.iter().copied(),0.5),"range":[rates.iter().copied().fold(1.,f64::min),rates.iter().copied().fold(0.,f64::max)],"rates":rates,"advertised_percent":ad}),
        Some(&rows),if ad.is_some_and(|v|avg*100.<v){"需关注"}else{"通过"},None,false))
}
async fn invalidate(c: &Probe<'_>) -> Result<Finding, String> {
    let prefix = padding(8192, &format!("{}-content", c.run.salt));
    let opts = Options {
        key: Some("content".into()),
        ..Default::default()
    };
    let a = c
        .ask("A 建缓存", format!("A{prefix}X"), opts.clone())
        .await?;
    let b = c
        .ask("A′ 改末字", format!("A{prefix}Y"), opts.clone())
        .await?;
    let d = c.ask("A″ 改首字", format!("B{prefix}Y"), opts).await?;
    let rates = [a.rate(), b.rate(), d.rate()];
    if rates.contains(&None) || ![&a, &b, &d].iter().all(|r| r.ok()) {
        return Ok(c.lack("A/A′/A″ 用量不完整", json!({"rates":rates}), None));
    }
    let bound = d.local_input.saturating_sub(8192) as i64 + d.input_delta.unwrap_or(0).max(0) + 128;
    let high = rates[2].unwrap() >= c.rule("high_cache") && d.n("cached").unwrap() > bound;
    let fixed = high
        && rates[0].unwrap() >= c.rule("high_cache")
        && rates[1].unwrap() >= c.rule("high_cache")
        && b.n("cached") == d.n("cached");
    let mut f = c.finding(
        format!(
            "建缓存 {:.1}%，改末字 {:.1}%，改首字 {:.1}%{}",
            rates[0].unwrap() * 100.,
            rates[1].unwrap() * 100.,
            rates[2].unwrap() * 100.,
            if high {
                "，缓存与内容无关，疑似伪造缓存"
            } else {
                ""
            }
        ),
        json!({"rates":rates,"shared_prefix_bound":bound}),
        None,
        if high { "异常" } else { "通过" },
        None,
        fixed,
    );
    f.strength = if fixed {
        "实测检出"
    } else if high {
        "疑似"
    } else {
        "未检出"
    }
    .into();
    Ok(f)
}
async fn ttft(c: &Probe<'_>) -> Result<Finding, String> {
    let text = padding(45000, &format!("{}-kv", c.run.salt));
    let opts = Options {
        key: Some("kv".into()),
        heavy: true,
        ..Default::default()
    };
    let a = c.ask("45K 冷请求", text.clone(), opts.clone()).await?;
    let b = c.ask("45K 热请求", text, opts).await?;
    let speed = ratio(b.ttft, a.ttft);
    let hot = b.rate();
    let metrics = json!({"cold_s":a.ttft,"warm_s":b.ttft,"warm_cold_ratio":speed,"warm_cache":hot});
    if speed.is_none() || hot.is_none() || !a.ok() || !b.ok() {
        return Ok(c.lack("冷/热 TTFT 或缓存样本不完整", metrics, None));
    }
    let paper = hot.unwrap() >= c.rule("high_cache") && speed.unwrap() >= c.rule("warm_ttft_ratio");
    Ok(c.finding(
        format!(
            "冷 {:.3}s，热 {:.3}s，热请求账面命中 {:.1}%{}",
            a.ttft.unwrap(),
            b.ttft.unwrap(),
            hot.unwrap() * 100.,
            if paper { "，疑似纸面缓存" } else { "" }
        ),
        metrics,
        None,
        if paper { "需关注" } else { "通过" },
        None,
        false,
    ))
}
async fn stickiness(c: &Probe<'_>) -> Result<Finding, String> {
    let text = padding(3072, &format!("{}-sticky", c.run.salt));
    let opts = Options {
        key: Some("sticky".into()),
        ..Default::default()
    };
    c.ask("建立粘性前缀", text.clone(), opts.clone()).await?;
    let spans = if c.run.spec.mode == "quick" {
        vec![0, 15]
    } else {
        vec![0, 15, 60]
    };
    let mut rates = vec![];
    for gap in &spans {
        if *gap > 0 {
            c.run.log(format!("缓存粘性等待 {gap} 秒"), c.id);
        }
        let at = std::time::Instant::now();
        c.run.wait(*gap as f64).await?;
        let waited = at.elapsed().as_secs_f64();
        let r = c
            .ask(&format!("间隔 {gap}s"), text.clone(), opts.clone())
            .await?;
        rates.push(json!({"interval_s":gap,"waited_s":waited,"rate":r.rate(),"seq":r.seq}));
    }
    let mut multi = vec![];
    for phase in ["建缓存", "重发"] {
        let jobs = ["a", "b"].into_iter().map(|s| {
            let text = text.clone();
            async move {
                c.ask(
                    &format!("会话 {s} {phase}"),
                    text,
                    Options {
                        key: Some(format!("session-{s}")),
                        session: s.into(),
                        ..Default::default()
                    },
                )
                .await
            }
        });
        let results = futures_util::future::join_all(jobs).await;
        for r in results {
            let row = r?;
            if phase == "重发" {
                multi.push(row.rate());
            }
        }
    }
    let metrics = json!({"intervals":rates,"sessions":multi});
    if rates.iter().any(|r| r["rate"].is_null()) || multi.contains(&None) {
        return Ok(c.lack("粘性样本缺少缓存字段", metrics, None));
    }
    let drop = rates[0]["rate"].as_f64().unwrap() >= c.rule("high_cache")
        && rates[1]["rate"].as_f64().unwrap() < c.rule("high_cache");
    Ok(c.finding(
        format!(
            "{} 个时间档与 2 个并发会话已采样{}",
            spans.len(),
            if drop {
                "，短间隔缓存回落，疑似无粘性轮询"
            } else {
                ""
            }
        ),
        metrics,
        None,
        if drop { "需关注" } else { "通过" },
        None,
        false,
    ))
}
pub fn sensitivity(c: &Probe<'_>) -> Finding {
    if c.run.spec.prices.as_ref().is_some_and(|p| p.input == 0.) {
        return c.lack("输入单价为零，折扣比例无定义", json!({}), Some(&[]));
    }
    let discount = c
        .run
        .spec
        .prices
        .as_ref()
        .map(|p| p.cached / p.input)
        .unwrap_or(c.rule("assumed_cache_ratio"));
    let base = c.result(16).and_then(|f| f.metrics["mean"].as_f64());
    let reference = base.unwrap_or(1.);
    let baseline = 1. - reference + reference * discount;
    let table:Vec<_>=[0.95,0.9,0.88,0.6].iter().map(|r|json!({"rate":r,"relative_input_cost":1.-r+r*discount,"increase":ratio(Some(1.-r+r*discount),Some(baseline)).map(|v|v-1.)})).collect();
    let rows: Vec<_> = c.traffic().into_iter().filter(|r| r.probe == 16).collect();
    c.finding(format!("按{}折扣比 {discount:.3} 推演 4 档缓存率",if c.run.spec.prices.is_some(){"所填单价"}else{"草案假设"}),
        json!({"basis":if c.run.spec.prices.is_some(){"所填单价"}else{"假设比，待确认"},"reference":reference,"reference_source":if base.is_some(){"实测"}else{"假设 100% 命中"},"discount":discount,"scenarios":table}),
        Some(&rows),"通过",None,false)
}
