use super::{ratio, Probe};
use crate::{
    core::{protocols::Options, tokenizer::padding},
    schemas::Finding,
};
use serde_json::{json, Value};

pub async fn execute(c: &Probe<'_>) -> Result<Finding, String> {
    match c.id {
        11 => ladder(c).await,
        12 => stability(c).await,
        14 => rounding(c).await,
        _ => unreachable!(),
    }
}
async fn ladder(c: &Probe<'_>) -> Result<Finding, String> {
    let mut table = vec![];
    for n in [0, 1000, 2000, 4000, 8000] {
        let r = c
            .ask(
                &format!("输入 +{n}"),
                format!(
                    "只回复 OK，样本 {}。\n{}",
                    c.run.salt,
                    padding(n, &format!("{}billing", c.run.salt))
                ),
                Options::default(),
            )
            .await?;
        table.push(json!({"padding":n,"expected":r.local_input,"reported":if r.ok(){r.n("input")}else{None},"seq":r.seq}));
    }
    let base = table[0].clone();
    for r in &mut table {
        let exp = r["expected"].as_i64().unwrap() - base["expected"].as_i64().unwrap();
        let actual = r["reported"]
            .as_i64()
            .zip(base["reported"].as_i64())
            .map(|(a, b)| a - b);
        r["expected_delta"] = json!(exp);
        r["reported_delta"] = json!(actual);
        r["difference"] = json!(actual.map(|a| a - exp));
    }
    if table.iter().any(|r| r["difference"].is_null()) {
        return Ok(c.lack("阶梯样本缺少完整输入用量", json!({"steps":table}), None));
    }
    let differences: Vec<_> = table[1..]
        .iter()
        .map(|r| r["difference"].as_f64().unwrap())
        .collect();
    let tol = c.rule("input_tolerance");
    let systematic = differences.iter().all(|d| *d > tol) || differences.iter().all(|d| *d < -tol);
    let bad = differences.iter().filter(|d| d.abs() > tol).count();
    Ok(c.finding(
        format!(
            "4 个非零阶梯，{bad} 档超出输入差额容差{}",
            if systematic {
                "，系统性偏离，疑似伪造输入"
            } else {
                ""
            }
        ),
        json!({"steps":table,"tolerance":tol}),
        None,
        if systematic {
            "异常"
        } else if bad > 0 {
            "需关注"
        } else {
            "通过"
        },
        None,
        systematic,
    ))
}
async fn stability(c: &Probe<'_>) -> Result<Finding, String> {
    let mut rows = vec![];
    for i in 1..=5 {
        rows.push(
            c.ask(&format!("相同请求 {i}"), "继续", Options::default())
                .await?,
        );
    }
    let values: Vec<_> = rows
        .iter()
        .filter(|r| r.ok())
        .map(|r| r.n("input"))
        .collect();
    if values.len() != 5 || values.contains(&None) {
        return Ok(c.lack("未取得五个输入计数", json!({"input":values}), None));
    }
    let distinct = values
        .iter()
        .collect::<std::collections::HashSet<_>>()
        .len();
    let brief = c
        .result(11)
        .map(|f| f.summary)
        .unwrap_or("本轮未取得阶梯结果".into());
    rows.extend(c.traffic().into_iter().filter(|r| r.probe == 11));
    Ok(c.finding(
        format!("5 次相同输入出现 {distinct} 种计数。固定输入的稳定性须结合变长阶梯解读。"),
        json!({"inputs":values,"ladder":brief}),
        Some(&rows),
        if distinct > 1 { "需关注" } else { "通过" },
        None,
        false,
    ))
}
pub fn output_audit(c: &Probe<'_>) -> Finding {
    let rows: Vec<_> = c
        .traffic()
        .into_iter()
        .filter(|r| r.ok() && (!r.text.is_empty() || !r.calls.is_empty()))
        .collect();
    let mut table = vec![];
    let mut bad = vec![];
    let mut valid = 0;
    for r in &rows {
        let difference = if r.calls.is_empty() {
            r.n("output")
                .zip(r.n("reasoning"))
                .map(|(a, b)| a - b - r.local_output as i64)
        } else {
            None
        };
        if let Some(d) = difference {
            valid += 1;
            if (d.abs() as f64) > c.rule("output_tolerance") {
                bad.push(r.seq);
            }
        }
        table.push(json!({"seq":r.seq,"visible":r.local_output,"reasoning":r.n("reasoning"),"reported":r.n("output"),
            "difference":difference,"scope":if r.calls.is_empty(){"可见文本与推理"}else{"工具参数另计"}}));
    }
    if valid == 0 {
        return c.lack(
            "缺少可见文本、输出或推理字段",
            json!({"rows":table}),
            Some(&rows),
        );
    }
    c.finding(
        format!("{valid} 条可比较输出中 {} 条超容差", bad.len()),
        json!({"rows":table,"flagged":bad}),
        Some(&rows),
        if bad.is_empty() {
            "通过"
        } else {
            "需关注"
        },
        None,
        false,
    )
}
async fn rounding(c: &Probe<'_>) -> Result<Finding, String> {
    let mut table = vec![];
    for (i, n) in [1, 3, 9, 17, 33].iter().enumerate() {
        let val = padding(*n, &format!("{}-tiny{i}", c.run.salt));
        let r = c
            .ask(
                &format!("小额样本 {n}"),
                format!("原样回显【{val}】"),
                Options {
                    effort: Some("low".into()),
                    ..Default::default()
                },
            )
            .await?;
        table.push(json!({"seq":r.seq,"visible":r.local_output,"output":r.n("output"),"reasoning":r.n("reasoning")}));
    }
    let usable: Vec<_> = table
        .iter()
        .filter(|r| r["output"].is_i64() && r["reasoning"].is_i64())
        .collect();
    if usable.len() < 3 {
        return Ok(c.lack("小额样本不足", json!({"rows":table}), None));
    }
    let values: Vec<_> = usable
        .iter()
        .map(|r| r["output"].as_i64().unwrap())
        .collect();
    let gcd = |mut a: i64, mut b: i64| {
        while b != 0 {
            let r = a % b;
            a = b;
            b = r;
        }
        a
    };
    let unit = values.iter().copied().reduce(gcd).unwrap();
    let minimum = values
        .iter()
        .collect::<std::collections::HashSet<_>>()
        .len()
        == 1
        && usable
            .iter()
            .map(|r| r["visible"].as_i64())
            .collect::<std::collections::HashSet<_>>()
            .len()
            > 1;
    let rounded = unit > 1
        && usable.iter().any(|r| {
            r["output"].as_i64().unwrap()
                != r["visible"].as_i64().unwrap() + r["reasoning"].as_i64().unwrap()
        });
    Ok(c.finding(format!("{} 个小额样本，输出计数公约数 {unit} tok{}",usable.len(),if minimum||rounded{"，疑似取整或最低门槛"}else{""}),
        json!({"rows":table,"gcd":unit,"possible_floor":if minimum{values.iter().min().copied()}else{None},"scope":"usage 粒度，逐笔实扣仍需账单"}),None,
        if minimum||rounded{"需关注"}else{"通过"},None,false))
}
pub async fn balance_snapshot(c: &Probe<'_>, label: &str) -> Result<Value, String> {
    for path in ["/v1/dashboard/billing/usage", "/api/user/self"] {
        let (r, value) = c.run.aux(c.id, label, path).await?;
        if r.error.is_some() || !value.is_object() {
            continue;
        }
        let d = value.get("data").unwrap_or(&value);
        for (field, kind, factor) in [
            ("balance_usd", "balance", Some(1.)),
            ("used_usd", "used", Some(1.)),
            ("total_usage", "used", Some(100.)),
            ("quota", "balance", c.run.spec.panel_units_per_usd),
            ("used_quota", "used", c.run.spec.panel_units_per_usd),
        ] {
            if let Some((amount, factor)) = d[field]
                .as_f64()
                .zip(factor)
                .filter(|(v, f)| *v >= 0. && *f > 0.)
            {
                return Ok(
                    json!({"usd":amount/factor,"kind":kind,"field":field,"factor":factor,"seq":r.seq,"path":path}),
                );
            }
        }
    }
    Ok(Value::Null)
}
pub fn deduction(before: &Value, after: &Value) -> Option<f64> {
    if before.is_null()
        || after.is_null()
        || ["kind", "field", "path", "factor"]
            .iter()
            .any(|k| before[*k] != after[*k])
    {
        return None;
    }
    let val = (after["usd"].as_f64()? - before["usd"].as_f64()?)
        * if before["kind"] == "used" { 1. } else { -1. };
    if val >= 0. {
        Some(val)
    } else {
        None
    }
}
pub fn reconcile(c: &Probe<'_>) -> Finding {
    let (start, end) = (c.memo("balance_before"), c.memo("balance_after"));
    let mut debit = deduction(&start, &end);
    let ledger = &c.run.spec.ledger;
    if let Some((b, a)) = ledger["before"].as_f64().zip(ledger["after"].as_f64()) {
        let amount = (a - b) * if ledger["kind"] == "used" { 1. } else { -1. }
            / ledger["units_per_usd"].as_f64().unwrap();
        debit = if amount >= 0. { Some(amount) } else { None };
    }
    let rows = c.run.rows();
    let official = {
        let d = c.run.data.lock().unwrap();
        if c.run.spec.prices.is_some() && d.budget.unknown == 0 {
            Some(d.budget.spent)
        } else {
            None
        }
    };
    let mult = ratio(debit, official);
    let segment = c.memo("cache_ledger");
    let segment_debit = deduction(&segment["before"], &segment["after"]);
    let seqs = segment["seqs"].as_array().cloned().unwrap_or_default();
    let cached_rows: Vec<_> = rows
        .iter()
        .filter(|r| seqs.contains(&json!(r.seq)))
        .collect();
    let mut cached_ratio = None;
    if let Some((p, debit)) = c.run.spec.prices.as_ref().zip(segment_debit) {
        if p.input > 0.
            && !cached_rows.is_empty()
            && cached_rows.iter().all(|r| {
                ["input", "cached", "output"]
                    .iter()
                    .all(|k| r.n(k).is_some())
            })
        {
            let cached = cached_rows
                .iter()
                .map(|r| r.n("cached").unwrap())
                .sum::<i64>() as f64;
            let other = cached_rows
                .iter()
                .map(|r| {
                    (r.n("input").unwrap() - r.n("cached").unwrap()) as f64 * p.input
                        + r.n("output").unwrap() as f64 * p.output
                })
                .sum::<f64>();
            cached_ratio = ratio(Some(debit * 1e6 - other), Some(cached * p.input));
        }
    }
    let metrics = json!({"before":start,"after":end,"deduction_usd":debit,"official_usd":official,"effective_multiplier":mult,
        "cache_segment":segment,"segment_deduction":segment_debit,"cache_effective_price_ratio":cached_ratio,
        "cache_effective_discount":cached_ratio.map(|r|1.-r),"scope":"窗口独占账户，假定非缓存输入与输出按所填单价扣除；外部并发消费会影响对账。"});
    if let Some(mult) = mult {
        c.finding(
            format!("该轮实扣 ${:.8}，有效倍率 {mult:.4}×", debit.unwrap()),
            metrics,
            Some(&rows),
            "通过",
            None,
            false,
        )
    } else {
        c.lack(
            if c.run.spec.prices.is_none() {
                "未配置官方单价，已跳过计算"
            } else {
                "余额不可用或计量不完整，可补填同轮测前与测后额度"
            },
            metrics,
            Some(&rows),
        )
    }
}
