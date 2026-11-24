use super::{ratio, Probe};
use crate::{
    core::{protocols::Options, tokenizer::padding},
    schemas::Finding,
};
use serde_json::{json, Value};
pub async fn execute(c: &Probe<'_>) -> Result<Finding, String> {
    match c.id {
        6 => injection(c).await,
        7 => {
            let prefix = padding(4096, &format!("{}-fresh", c.run.salt));
            let opts = Options {
                key: Some("cold-unique".into()),
                ..Default::default()
            };
            let cold = c.ask("全新盐冷启动", prefix.clone(), opts.clone()).await?;
            c.set("cold_seq", json!(cold.seq));
            c.ask("相同前缀热样本", prefix, opts).await?;
            Ok(audit_cache(c))
        }
        9 => {
            c.ask(
                "长输出速度样本",
                format!("样本 {}。连续输出 640 次字符 X，不加空格。", c.run.salt),
                Options {
                    limit: 1024,
                    ..Default::default()
                },
            )
            .await?;
            Ok(stream_audit(c))
        }
        10 => native(c).await,
        _ => unreachable!(),
    }
}
async fn injection(c: &Probe<'_>) -> Result<Finding, String> {
    let prompt = format!("样本 {}。只回答 OK。", c.run.salt);
    let full = c
        .ask(
            "Profile 基线",
            prompt.clone(),
            Options {
                bare: Some(false),
                ..Default::default()
            },
        )
        .await?;
    let bare = c
        .ask(
            "极简裸请求对照",
            prompt,
            Options {
                bare: Some(true),
                ..Default::default()
            },
        )
        .await?;
    let mut metrics = json!({"profile_delta":full.input_delta,"bare_delta":bare.input_delta,
        "profile_share":ratio(full.input_delta.map(|v|v as f64),full.n("input").map(|v|v as f64))});
    let Some((a, b)) = full
        .input_delta
        .zip(bare.input_delta)
        .filter(|_| full.ok() && bare.ok())
    else {
        return Ok(c.lack("A/B 请求缺少可比较的输入计数", metrics, None));
    };
    let excess = a.max(0);
    let usable = full
        .n("cached")
        .filter(|v| *v <= full.n("input").unwrap_or(0));
    let lower = usable.map(|v| (v - full.local_input as i64).max(0));
    let upper = usable.map(|v| v.min(excess));
    metrics["injection_cache_bounds"] = json!([lower, upper]);
    metrics["input_inflation_2000"] = json!((2000 + excess) as f64 / 2000.);
    metrics["estimated_cost_ratio_2000"] = Value::Null;
    if let (Some(p), Some(l), Some(u)) = (&c.run.spec.prices, lower, upper) {
        if p.input > 0. {
            let mut values = vec![
                (2000. * p.input + (excess - l) as f64 * p.input + l as f64 * p.cached)
                    / (2000. * p.input),
                (2000. * p.input + (excess - u) as f64 * p.input + u as f64 * p.cached)
                    / (2000. * p.input),
            ];
            values.sort_by(f64::total_cmp);
            metrics["estimated_cost_ratio_2000"] = json!(values);
        }
    }
    let tol = c.rule("input_tolerance");
    let text = if (a - b) as f64 > tol {
        "Profile 侧额外输入较多，疑似按客户端分流"
    } else if (a.min(b) as f64) > tol {
        "两种请求均有额外输入，疑似固定注入"
    } else {
        "两种请求的本地输入差额接近基线"
    };
    Ok(c.finding(
        format!("Profile 差额 {a:+} tok，裸请求 {b:+} tok。{text}"),
        metrics,
        None,
        if a.max(b) as f64 > tol {
            "需关注"
        } else {
            "通过"
        },
        None,
        false,
    ))
}
pub fn audit_cache(c: &Probe<'_>) -> Finding {
    let rows: Vec<_> = c
        .traffic()
        .into_iter()
        .filter(|r| r.n("cached").is_some())
        .collect();
    let cold = rows
        .iter()
        .find(|r| Some(r.seq as u64) == c.memo("cold_seq").as_u64());
    let non128: Vec<_> = rows
        .iter()
        .filter(|r| r.n("cached").unwrap() % 128 != 0)
        .map(|r| r.seq)
        .collect();
    let below: Vec<_> = rows
        .iter()
        .filter(|r| r.n("cached").unwrap() > 0 && r.n("cached").unwrap() < 1024)
        .map(|r| r.seq)
        .collect();
    let metrics = json!({"non128":non128,"below1024":below,"cold_rate":cold.and_then(|r|r.rate()),"cold_seq":c.memo("cold_seq")});
    if rows.is_empty() || cold.is_none() {
        return c.lack("缺少冷启动缓存明细", metrics, Some(&rows));
    }
    let high = cold
        .and_then(|r| r.rate())
        .is_some_and(|v| v >= c.rule("high_cache"));
    let invalid = rows
        .iter()
        .filter(|r| {
            r.n("cached").unwrap() > 0
                && (r.n("cached").unwrap() % 128 != 0 || r.n("cached").unwrap() < 1024)
        })
        .count();
    let text = format!(
        "{} 个缓存计数中 {invalid} 个违反粒度或起跳门槛{}{}",
        rows.len(),
        if below.is_empty() {
            ""
        } else {
            "，低于 1024 的非零计数疑似自算"
        },
        if high {
            "，冷启动异常命中，疑似伪造缓存"
        } else {
            ""
        }
    );
    let mut f = c.finding(
        text,
        metrics,
        Some(&rows),
        if !non128.is_empty() || high {
            "异常"
        } else if invalid > 0 {
            "需关注"
        } else {
            "通过"
        },
        None,
        !non128.is_empty(),
    );
    f.strength = if !non128.is_empty() {
        "实测检出"
    } else if invalid > 0 || high {
        "疑似"
    } else {
        "未检出"
    }
    .into();
    f
}
pub fn invisible(c: &Probe<'_>) -> Finding {
    let rows: Vec<_> = c
        .traffic()
        .into_iter()
        .filter(|r| !r.text.is_empty())
        .collect();
    let re = regex::Regex::new(r"[\p{Cf}\p{Cc}]").unwrap();
    let mut hits = vec![];
    for r in &rows {
        for (i, ch) in r.text.chars().enumerate() {
            if !['\n', '\r', '\t'].contains(&ch) && re.is_match(&ch.to_string()) {
                hits.push(
                    json!({"seq":r.seq,"position":i,"codepoint":format!("U+{:04X}",ch as u32)}),
                );
            }
        }
    }
    if rows.is_empty() {
        return c.lack("没有可扫描的返回文本", json!({}), Some(&rows));
    }
    let mut f = c.finding(
        format!(
            "扫描 {} 条回答，发现 {} 个不可见字符",
            rows.len(),
            hits.len()
        ),
        json!({"hits":hits}),
        Some(&rows),
        if hits.is_empty() {
            "通过"
        } else {
            "需关注"
        },
        None,
        false,
    );
    if !hits.is_empty() {
        f.strength = "实测检出".into();
    }
    f
}
pub fn stream_audit(c: &Probe<'_>) -> Finding {
    let rows: Vec<_> = c.traffic().into_iter().filter(|r| r.stream).collect();
    if rows.is_empty() {
        return c.lack("无流式请求", json!({}), Some(&rows));
    }
    let finished = rows.iter().filter(|r| r.ok()).count();
    let usage = rows
        .iter()
        .filter(|r| {
            ["input", "output", "total"]
                .iter()
                .all(|k| r.n(k).is_some())
        })
        .count();
    let mut timings = vec![];
    let mut timeouts = vec![];
    for r in &rows {
        if !r.ok()
            && [30., 60.]
                .iter()
                .any(|t| (r.elapsed - t).abs() <= c.rule("timeout_window_s"))
        {
            timeouts.push(json!({"seq":r.seq,"seconds":r.elapsed}));
        }
        let ch = &r.chunks;
        if ch.len() < 20 {
            continue;
        }
        let q = ch.len() / 4;
        let speed = |items: &[Value]| {
            ratio(
                Some(
                    items[1..]
                        .iter()
                        .map(|v| v["tokens"].as_f64().unwrap_or(0.))
                        .sum(),
                ),
                Some(
                    items.last().unwrap()["t"].as_f64().unwrap() - items[0]["t"].as_f64().unwrap(),
                ),
            )
        };
        let front = speed(&ch[..q]);
        let tail = speed(&ch[ch.len() - q..]);
        let max_itl = ch
            .windows(2)
            .map(|p| p[1]["t"].as_f64().unwrap() - p[0]["t"].as_f64().unwrap())
            .fold(0., f64::max);
        timings.push(json!({"seq":r.seq,"first_quarter_tps":front,"last_quarter_tps":tail,"tail_ratio":ratio(tail,front),"max_itl_s":max_itl}));
    }
    let decays = timings
        .iter()
        .filter(|t| {
            t["tail_ratio"]
                .as_f64()
                .is_some_and(|v| v < c.rule("tail_ratio"))
        })
        .count();
    let bad = finished != rows.len() || usage != rows.len() || decays > 0;
    c.finding(format!("{finished}/{} 正常结束，{usage}/{} 返回完整用量，{decays} 个长输出样本尾段减速",rows.len(),rows.len()),
        json!({"completed":finished,"usage_complete":usage,"timings":timings,"near_timeout":timeouts,"timing_scope":"按语义块到达时间测量；单块多 token 的块内 ITL 不可观测。"}),Some(&rows),if bad{"需关注"}else{"通过"},None,false)
}
async fn native(c: &Probe<'_>) -> Result<Finding, String> {
    let r = c
        .ask(
            "store=false",
            "只回复 OK",
            Options {
                extra: json!({"store":false}),
                ..Default::default()
            },
        )
        .await?;
    let mut checks =
        json!({"id":r.response_id.is_some(),"usage":r.usage.is_some(),"正常完结":r.ok()});
    if c.run.protocol() == "responses" {
        checks["原生事件"] = json!(["response.output_text.delta", "response.completed"]
            .iter()
            .all(|e| r.events.iter().any(|v| v == e)));
        let stored = c
            .ask(
                "建立可续接响应",
                format!("本轮口令为 {}，先回答 OK。", c.run.salt),
                Options {
                    extra: json!({"store":true}),
                    ..Default::default()
                },
            )
            .await?;
        if let Some(id) = stored.response_id {
            let follow = c
                .ask(
                    "previous_response_id 续接",
                    "请复述前一轮给出的口令。",
                    Options {
                        extra: json!({"previous_response_id":id,"store":false}),
                        ..Default::default()
                    },
                )
                .await?;
            checks["续接请求受理"] = json!(follow.ok());
            checks["续接记忆"] = json!(follow.ok() && follow.text.contains(&c.run.salt));
        } else {
            checks["续接请求受理"] = json!(false);
        }
    }
    Ok(c.checked(checks, json!({"protocol":c.run.protocol()}), false))
}
