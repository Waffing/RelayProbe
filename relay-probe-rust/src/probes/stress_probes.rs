use super::{mean, percentile, Probe};
use crate::{
    core::protocols::Options,
    schemas::{Finding, Row},
};
use futures_util::{stream::FuturesUnordered, FutureExt, StreamExt};
use serde_json::{json, Value};
use std::{collections::BTreeMap, time::Instant};

fn stop_reason(rows: &[Row]) -> &'static str {
    if rows.len() >= 2
        && rows[rows.len() - 2..]
            .iter()
            .all(|r| matches!(r.status, Some(429 | 403)))
    {
        "连续两次 429/403"
    } else if !rows.is_empty()
        && rows.iter().filter(|r| !r.ok()).count() as f64 / rows.len() as f64 > 0.30
    {
        "当前完成窗口错误率 >30%"
    } else {
        ""
    }
}
fn stats(rows: &[Row], duration: f64) -> Value {
    let good = rows.iter().filter(|r| r.ok()).count();
    let mut codes = BTreeMap::new();
    for r in rows {
        *codes
            .entry(
                r.status
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| r.error.clone().unwrap_or("无状态".into())),
            )
            .or_insert(0) += 1;
    }
    let outputs: Vec<_> = rows
        .iter()
        .filter(|r| r.ok())
        .map(|r| r.n("output"))
        .collect();
    json!({"success":good,"failed":rows.len()-good,"statuses":codes,
        "latency_p50":percentile(rows.iter().map(|r|r.elapsed),0.5),"latency_p95":percentile(rows.iter().map(|r|r.elapsed),0.95),
        "latency_p99":percentile(rows.iter().map(|r|r.elapsed),0.99),"ttft_mean":mean(rows.iter().map(|r|r.ttft)),
        "elapsed_s":duration,"req_s":rows.len() as f64/duration,
        "tok_s":if !outputs.is_empty()&&!outputs.contains(&None){Some(outputs.iter().flatten().sum::<i64>() as f64/duration)}else{None},
        "cost":if !rows.is_empty()&&rows.iter().all(|r|r.cost.is_some()){Some(rows.iter().filter_map(|r|r.cost).sum::<f64>())}else{None},
        "seqs":rows.iter().map(|r|r.seq).collect::<Vec<_>>()})
}
pub async fn ramp(c: &Probe<'_>) -> Result<(), String> {
    let mut record = json!({"stages":[],"critical":null,"stop":""});
    c.set("stress", record.clone());
    let mut levels = vec![1, 5, 10, 20];
    if c.run.spec.allow_50 {
        levels.push(50);
    }
    for level in levels {
        let start = Instant::now();
        let group = c.run.cancel.child_token();
        let mut pending = FuturesUnordered::new();
        for i in 0..level {
            let token = group.clone();
            pending.push(async move {
                c.ask(
                    &format!("{level} 并发 · {}", i + 1),
                    format!("样本 {}-{level}-{i}，只回复 OK。", c.run.salt),
                    Options {
                        cancel: Some(token),
                        track_failure: false,
                        limit: 64,
                        ..Default::default()
                    },
                )
                .await
            });
        }
        let mut done = vec![];
        let mut error = None;
        let mut reason = String::new();
        while let Some(result) = pending.next().await {
            match result {
                Ok(row) => {
                    done.push(row);
                    if reason.is_empty() {
                        reason = stop_reason(&done).into();
                    }
                }
                Err(e) => {
                    if error.is_none() {
                        error = Some(e);
                    }
                }
            }
            if error.is_some() || !reason.is_empty() {
                group.cancel();
            }
        }
        let prefix = format!("{level} 并发 · ");
        let rows: Vec<_> = c
            .rows()
            .into_iter()
            .filter(|r| r.label.starts_with(&prefix))
            .collect();
        let mut stage = stats(&rows, start.elapsed().as_secs_f64());
        stage["level"] = json!(level);
        record["stages"].as_array_mut().unwrap().push(stage);
        if !reason.is_empty() {
            record["critical"] = json!(level);
            record["stop"] = json!(reason);
            c.run.log(format!("{level} 并发停压，{reason}"), c.id);
        }
        c.set("stress", record.clone());
        if let Some(e) = error {
            return Err(e);
        }
        if !reason.is_empty() {
            break;
        }
    }
    Ok(())
}
pub fn result(c: &Probe<'_>) -> Finding {
    let record = c.memo("stress");
    let stages = record["stages"].as_array().cloned().unwrap_or_default();
    let seqs: Vec<_> = stages
        .iter()
        .flat_map(|s| s["seqs"].as_array().cloned().unwrap_or_default())
        .collect();
    let rows: Vec<_> = c
        .traffic()
        .into_iter()
        .filter(|r| seqs.contains(&json!(r.seq)))
        .collect();
    if stages.is_empty() {
        return c.lack("未完成并发阶梯", json!({}), Some(&rows));
    }
    let critical = record["critical"].as_u64();
    let levels = stages
        .iter()
        .map(|s| s["level"].to_string())
        .collect::<Vec<_>>()
        .join(" → ");
    let ending = if let Some(n) = critical {
        format!("，临界 {n} 并发，{}", record["stop"].as_str().unwrap_or(""))
    } else {
        "，窗口未触发停压".into()
    };
    c.finding(
        format!("已测并发档 {levels}{ending}"),
        record,
        Some(&rows),
        if critical.is_some() {
            "异常"
        } else {
            "通过"
        },
        None,
        false,
    )
}
pub async fn sustained(c: &Probe<'_>) -> Result<Finding, String> {
    if !c.memo("stress")["critical"].is_null() {
        return Ok(c.lack("阶梯已触发停压，持续速率未启动", json!({}), None));
    }
    let rpm = c.run.spec.controls.sustained_rpm;
    let start = Instant::now();
    let group = c.run.cancel.child_token();
    let mut pending = FuturesUnordered::new();
    let mut sent = 0;
    let mut done = vec![];
    let mut completed = BTreeMap::new();
    let mut reason = String::new();
    let mut error = None;
    loop {
        let now = start.elapsed().as_secs_f64();
        if now >= 60. && pending.is_empty() {
            break;
        }
        if sent < rpm && now < 60. && now >= sent as f64 * 60. / rpm as f64 {
            sent += 1;
            if pending.len() < if c.run.spec.allow_50 { 50 } else { 20 } {
                let token = group.clone();
                let n = sent;
                pending.push(
                    async move {
                        c.ask(
                            &format!("匀速 {n}"),
                            format!("只回复 OK。{}-{n}", c.run.salt),
                            Options {
                                cancel: Some(token),
                                track_failure: false,
                                limit: 64,
                                ..Default::default()
                            },
                        )
                        .await
                    }
                    .boxed(),
                );
            }
        }
        let wake = (sent as f64 * 60. / rpm as f64).min(60.);
        let delay = (wake - start.elapsed().as_secs_f64()).max(0.);
        tokio::select! {
            result=pending.next(),if !pending.is_empty()=>{
                if let Some(result)=result{
                    match result{Ok(row)=>{completed.insert(row.seq,start.elapsed().as_secs_f64());done.push(row);reason=stop_reason(&done).into();},Err(e)=>{error=Some(e);}}
                }
            }
            result=c.run.wait(delay),if now<60.=>{
                if let Err(e)=result{error=Some(e);}
            }
        }
        if error.is_some() || !reason.is_empty() {
            group.cancel();
            break;
        }
    }
    while let Some(result) = pending.next().await {
        if let Ok(row) = result {
            completed.insert(row.seq, start.elapsed().as_secs_f64());
            done.push(row);
        }
    }
    if let Some(e) = error {
        return Err(e);
    }
    let elapsed = start.elapsed().as_secs_f64();
    let rows = c.rows();
    let first = rows.iter().find(|r| !r.ok()).map(|r| r.seq);
    let mut windows = vec![];
    for t in (0..60).step_by(10) {
        let batch: Vec<_> = done
            .iter()
            .filter(|r| {
                completed
                    .get(&r.seq)
                    .is_some_and(|v| *v >= t as f64 && *v < (t + 10) as f64)
            })
            .collect();
        windows.push(json!({"from_s":t,"to_s":t+10,"completed":batch.len(),
            "error_rate":if batch.is_empty(){None}else{Some(batch.iter().filter(|r|!r.ok()).count() as f64/batch.len() as f64)}}));
    }
    let success = rows.iter().filter(|r| r.ok()).count();
    let mut metrics = stats(&rows, elapsed);
    for (k,v) in json!({"target_rpm":rpm,"observed_success_rpm":success as f64*60./elapsed,"first_error_seq":first,
        "first_error_at_s":first.and_then(|s|completed.get(&s).copied()),"windows":windows,"scope":"已达成功速率；未触发限流时，真实上限待测。","stop":reason}).as_object().unwrap(){metrics[k]=v.clone();}
    Ok(c.finding(
        format!("{elapsed:.1}s 内成功 {success}/{} 次", rows.len()),
        metrics,
        None,
        if first.is_some() {
            "需关注"
        } else {
            "通过"
        },
        None,
        false,
    ))
}
