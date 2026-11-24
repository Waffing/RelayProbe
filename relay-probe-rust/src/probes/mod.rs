pub mod billing_probes;
pub mod cache_probes;
pub mod model_probes;
pub mod quality_probes;
pub mod scoring_probes;
pub mod signatures;
pub mod stress_probes;

use crate::{
    core::{protocols::Options, runner::Run},
    schemas::{Finding, Row},
};
use serde_json::{json, Value};

pub fn mean(values: impl IntoIterator<Item = Option<f64>>) -> Option<f64> {
    let values: Vec<_> = values.into_iter().flatten().collect();
    if values.is_empty() {
        None
    } else {
        Some(values.iter().sum::<f64>() / values.len() as f64)
    }
}
pub fn percentile(values: impl IntoIterator<Item = f64>, p: f64) -> Option<f64> {
    let mut values: Vec<_> = values.into_iter().collect();
    if values.is_empty() {
        return None;
    }
    values.sort_by(f64::total_cmp);
    let at = (values.len() - 1) as f64 * p;
    Some(
        values[at.floor() as usize]
            + (values[at.ceil() as usize] - values[at.floor() as usize]) * at.fract(),
    )
}
pub fn ratio(a: Option<f64>, b: Option<f64>) -> Option<f64> {
    let (a, b) = (a?, b?);
    if b == 0. {
        None
    } else {
        Some(a / b)
    }
}
pub fn name(id: usize) -> String {
    crate::schemas::defaults()["probes"][id.saturating_sub(1)]["name"]
        .as_str()
        .unwrap_or("协议预检")
        .to_owned()
}
pub fn question(salt: &str, i: usize) -> (String, String) {
    use rand::{Rng, SeedableRng};
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    format!("{salt}/{i}").hash(&mut h);
    let mut rng = rand::rngs::StdRng::seed_from_u64(h.finish());
    let (a, b, k) = (
        rng.gen_range(50..500),
        rng.gen_range(5..42),
        rng.gen_range(3..20),
    );
    let (expr, answer) = match i % 4 {
        0 => (format!("({a} + {b}) * {k}"), (a + b) * k),
        1 => (format!("({a} - {b}) * {k}"), (a - b) * k),
        2 => (format!("({a} * {b}) % {k}"), (a * b) % k),
        _ => (format!("({a} * {b}) // {k}"), (a * b) / k),
    };
    (
        format!("计算表达式 {expr} 的整数结果。只返回整数。"),
        answer.to_string(),
    )
}
pub fn nonce() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}
pub struct Probe<'a> {
    pub run: &'a Run,
    pub id: usize,
}
impl<'a> Probe<'a> {
    pub fn new(run: &'a Run, id: usize) -> Self {
        Self { run, id }
    }
    pub fn rows(&self) -> Vec<Row> {
        self.run
            .rows()
            .into_iter()
            .filter(|r| r.probe == self.id)
            .collect()
    }
    pub fn traffic(&self) -> Vec<Row> {
        self.run
            .rows()
            .into_iter()
            .filter(|r| r.method == "POST")
            .collect()
    }
    pub fn rule(&self, key: &str) -> f64 {
        self.run.spec.rule(key)
    }
    pub fn memo(&self, key: &str) -> Value {
        self.run
            .data
            .lock()
            .unwrap()
            .memo
            .get(key)
            .cloned()
            .unwrap_or(Value::Null)
    }
    pub fn set(&self, key: &str, value: Value) {
        self.run.data.lock().unwrap().memo.insert(key.into(), value);
    }
    pub fn result(&self, id: usize) -> Option<Finding> {
        self.run.data.lock().unwrap().findings.get(&id).cloned()
    }
    pub async fn ask(
        &self,
        label: &str,
        prompt: impl Into<Value>,
        opts: Options,
    ) -> Result<Row, String> {
        self.run.ask(self.id, label, prompt.into(), opts).await
    }
    pub fn finding(
        &self,
        summary: impl Into<String>,
        metrics: Value,
        rows: Option<&[Row]>,
        status: &str,
        score: Option<f64>,
        hard: bool,
    ) -> Finding {
        let mut evidence: Vec<_> = rows
            .map(|r| r.to_vec())
            .unwrap_or_else(|| self.rows())
            .iter()
            .map(|r| r.seq)
            .collect();
        evidence.sort_unstable();
        evidence.dedup();
        Finding {
            id: self.id,
            name: name(self.id),
            status: status.into(),
            strength: match status {
                "异常" => "实测检出",
                "需关注" => "疑似",
                _ => "未检出",
            }
            .into(),
            summary: summary.into(),
            samples: evidence.len(),
            evidence,
            metrics,
            score,
            hard,
        }
    }
    pub fn lack(
        &self,
        summary: impl Into<String>,
        metrics: Value,
        rows: Option<&[Row]>,
    ) -> Finding {
        self.finding(summary, metrics, rows, "证据不足", None, false)
    }
    pub fn checked(&self, checks: Value, mut metrics: Value, quantified: bool) -> Finding {
        let checks = checks.as_object().unwrap();
        let total = checks.len();
        let hits = checks.values().filter(|v| v == &&Value::Bool(true)).count();
        metrics["checks"] = json!(checks);
        self.finding(
            format!("{hits}/{total} 项校验通过"),
            metrics,
            None,
            if hits == total { "通过" } else { "异常" },
            if quantified && total > 0 {
                Some(hits as f64 / total as f64)
            } else {
                None
            },
            false,
        )
    }
}
pub fn selected(spec: &crate::schemas::Spec) -> Vec<usize> {
    let defaults = crate::schemas::defaults();
    let mut ids = spec.probe_ids.clone().unwrap_or_else(|| {
        defaults["modes"][&spec.mode]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i.as_u64().unwrap() as usize)
            .collect()
    });
    if spec.probe_ids.is_none() {
        ids.extend(&spec.expensive);
    }
    ids.retain(|i| ![35, 36, 40].contains(i) || spec.expensive.contains(i));
    ids.sort_unstable();
    ids.dedup();
    ids
}
pub fn estimate(spec: &crate::schemas::Spec, ids: &[usize]) -> Value {
    let mut calls = 1;
    let mut pads = 0;
    for id in ids {
        calls += match id {
            1 => 13,
            2 => {
                if spec.mode == "quick" {
                    8
                } else {
                    12
                }
            }
            3 => 4,
            4 => 2,
            5 => 1,
            6 => 2,
            7 => 2,
            9 => 1,
            10 => 3,
            11 => 5,
            12 => 5,
            14 => 5,
            15 => 4,
            16 => spec.controls.cache_repeats,
            17 => 3,
            18 => 2,
            19 => {
                if spec.mode == "quick" {
                    7
                } else {
                    8
                }
            }
            22 => usize::from(!ids.contains(&6)),
            24 => 6,
            26 => 2,
            28 => 2,
            29 | 30 | 35 => 1,
            31 => 5,
            32 => 2,
            33 | 34 | 36 => 4,
            40 => spec.controls.sustained_rpm,
            _ => 0,
        };
        pads += match id {
            5 => 100_000,
            7 => 8192,
            11 => 15000,
            16 => 4096 * spec.controls.cache_repeats,
            17 => 24576,
            18 => 90000,
            19 => 24576,
            36 => 424000,
            _ => 0,
        };
    }
    if ids.iter().any(|i| [37, 38, 39].contains(i)) {
        calls += 36 + if spec.allow_50 { 50 } else { 0 };
    }
    if ids.contains(&15) && ids.contains(&16) {
        calls += 4;
    }
    json!({"requests_approx":calls,"tokens_approx":calls*512+pads,"basis":"按勾选项目与长前缀规划估量；预检降级、失败和停压会改变实际量。"})
}
pub fn active(id: usize) -> bool {
    matches!(id,1..=7|9..=12|14|16..=19|22|26|28..=40)
}
pub async fn execute(c: &Probe<'_>) -> Result<Finding, String> {
    match c.id {
        1..=5 => scoring_probes::execute(c).await,
        6 | 7 | 9 | 10 => quality_probes::execute(c).await,
        11 | 12 | 14 => billing_probes::execute(c).await,
        16..=19 => cache_probes::execute(c).await,
        22 | 26 => signatures::execute(c).await,
        28..=36 => model_probes::execute(c).await,
        37..=39 => {
            stress_probes::ramp(c).await?;
            Ok(stress_probes::result(c))
        }
        40 => stress_probes::sustained(c).await,
        _ => unreachable!(),
    }
}
pub fn passive(c: &Probe<'_>) -> Option<Finding> {
    match c.id {
        7 => Some(quality_probes::audit_cache(c)),
        8 => Some(quality_probes::invisible(c)),
        9 => Some(quality_probes::stream_audit(c)),
        13 => Some(billing_probes::output_audit(c)),
        15 => Some(billing_probes::reconcile(c)),
        20 => Some(cache_probes::sensitivity(c)),
        21 | 23 | 24 | 25 | 27 => Some(signatures::passive(c)),
        37..=39 => Some(stress_probes::result(c)),
        _ => None,
    }
}
