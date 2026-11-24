use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Controls {
    pub connect_s: f64,
    pub read_s: f64,
    pub heavy_s: f64,
    pub max_requests: usize,
    pub max_tokens: usize,
    pub consecutive_failures: usize,
    pub cache_repeats: usize,
    pub sustained_rpm: usize,
    pub budget_usd: Option<f64>,
    pub weights: Vec<f64>,
    pub rules: BTreeMap<String, f64>,
}
impl Default for Controls {
    fn default() -> Self {
        Self {
            connect_s: 15.,
            read_s: 60.,
            heavy_s: 150.,
            max_requests: 180,
            max_tokens: 600_000,
            consecutive_failures: 3,
            cache_repeats: 8,
            sustained_rpm: 30,
            budget_usd: None,
            weights: vec![1.; 5],
            rules: serde_json::from_value(defaults()["controls"]["rules"].clone()).unwrap(),
        }
    }
}
pub fn defaults() -> Value {
    serde_json::from_str(include_str!("../assets/defaults.json")).unwrap()
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prices {
    pub input: f64,
    pub cached: f64,
    pub output: f64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Spec {
    pub base_url: String,
    pub model: String,
    pub name: String,
    pub protocol: String,
    pub profile_id: String,
    pub bare: bool,
    pub mode: String,
    pub probe_ids: Option<Vec<usize>>,
    pub expensive: Vec<usize>,
    pub allow_50: bool,
    pub advertised_cache: Option<f64>,
    pub panel_units_per_usd: Option<f64>,
    pub prices: Option<Prices>,
    pub ledger: Value,
    pub controls: Controls,
    pub fingerprints: Vec<i64>,
}
impl Default for Spec {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            model: String::new(),
            name: "未命名渠道".into(),
            protocol: "auto".into(),
            profile_id: "builtin".into(),
            bare: false,
            mode: "quick".into(),
            probe_ids: None,
            expensive: vec![],
            allow_50: false,
            advertised_cache: None,
            panel_units_per_usd: None,
            prices: None,
            ledger: json!({"kind":"balance","before":null,"after":null,"units_per_usd":1}),
            controls: Controls::default(),
            fingerprints: vec![4233, 4157],
        }
    }
}
impl Spec {
    pub fn rule(&self, key: &str) -> f64 {
        self.controls.rules[key]
    }
    pub fn validate(&mut self) -> Result<(), String> {
        let valid = || -> bool {
            let c = &self.controls;
            !self.model.is_empty()
                && self.model.len() <= 800
                && self.name.len() <= 400
                && ["auto", "responses", "chat"].contains(&self.protocol.as_str())
                && ["quick", "full", "stress"].contains(&self.mode.as_str())
                && self.probe_ids.as_ref().is_none_or(|ids| {
                    !ids.is_empty() && ids.len() <= 40 && ids.iter().all(|i| (1..=40).contains(i))
                })
                && self.expensive.iter().all(|i| [35, 36, 40].contains(i))
                && (1..=2000).contains(&c.max_requests)
                && (1..=10_000_000).contains(&c.max_tokens)
                && (1..=20).contains(&c.consecutive_failures)
                && (2..=40).contains(&c.cache_repeats)
                && (1..=120).contains(&c.sustained_rpm)
                && c.connect_s > 0.
                && c.connect_s <= 300.
                && c.read_s > 0.
                && c.read_s <= 900.
                && c.heavy_s > 0.
                && c.heavy_s <= 1800.
                && c.budget_usd.is_none_or(|v| v > 0.)
                && c.weights.len() == 5
                && c.weights.iter().all(|w| *w >= 0.)
                && c.weights.iter().sum::<f64>() > 0.
                && self
                    .advertised_cache
                    .is_none_or(|v| (0.0..=100.).contains(&v))
                && self.panel_units_per_usd.is_none_or(|v| v > 0.)
                && self
                    .prices
                    .as_ref()
                    .is_none_or(|p| p.input >= 0. && p.cached >= 0. && p.output >= 0.)
                && self.fingerprints.len() <= 256
        };
        if !valid() {
            return Err("输入字段格式无效".into());
        }
        let standard: BTreeMap<String, f64> =
            serde_json::from_value(defaults()["controls"]["rules"].clone()).unwrap();
        for (key, val) in &self.controls.rules {
            if !standard.contains_key(key) || *val < 0. || !val.is_finite() {
                return Err("规则字段或阈值无效".into());
            }
        }
        for (key, val) in standard {
            self.controls.rules.entry(key).or_insert(val);
        }
        for key in [
            "high_cache",
            "warm_ttft_ratio",
            "answer_ttft_ratio",
            "tail_ratio",
        ] {
            if !(self.rule(key) > 0. && self.rule(key) <= 1.) {
                return Err("比例阈值须在 0 到 1 之间".into());
            }
        }
        if self.rule("effort_ratio") < 1.
            || self.rule("duration_ratio") < 1.
            || self.rule("burst_gap_s") <= 0.
            || self.rule("high_injection") < 1.
            || self.rule("assumed_cache_ratio") > 1.
            || self.rule("score_c") > self.rule("score_b")
            || self.rule("score_b") > self.rule("score_a")
            || self.rule("score_a") > 100.
        {
            return Err("规则阈值范围无效".into());
        }
        let mut ledger = Spec::default().ledger;
        let incoming = self.ledger.as_object().ok_or("余额字段格式无效")?;
        for (k, v) in incoming {
            if !["kind", "before", "after", "units_per_usd"].contains(&k.as_str()) {
                return Err("余额字段格式无效".into());
            }
            ledger[k] = v.clone();
        }
        if !["balance", "used"].contains(&ledger["kind"].as_str().unwrap_or(""))
            || ledger["units_per_usd"].as_f64().is_none_or(|v| v <= 0.)
            || ["before", "after"]
                .iter()
                .any(|k| !ledger[*k].is_null() && ledger[*k].as_f64().is_none_or(|v| v < 0.))
        {
            return Err("余额字段格式无效".into());
        }
        self.ledger = ledger;
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Profile {
    #[serde(default)]
    pub id: String,
    pub name: String,
    #[serde(default = "default_client")]
    pub client: String,
    #[serde(default = "default_source")]
    pub source: String,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default = "empty_object")]
    pub body: Value,
    #[serde(default)]
    pub baseline_tokens: usize,
}
fn default_client() -> String {
    "Codex".into()
}
fn default_source() -> String {
    "自建基准模板".into()
}
fn default_protocol() -> String {
    "responses".into()
}
fn empty_object() -> Value {
    json!({})
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Row {
    pub seq: usize,
    pub probe: usize,
    pub label: String,
    pub protocol: String,
    pub disguised: bool,
    pub method: String,
    pub path: String,
    pub headers: Value,
    pub body: Value,
    pub response_headers: Value,
    pub status: Option<u16>,
    pub error: Option<String>,
    pub snippet: String,
    pub elapsed: f64,
    pub phases: Value,
    pub ttft: Option<f64>,
    pub chunks: Vec<Value>,
    pub events: Vec<String>,
    pub stream: bool,
    pub complete: bool,
    pub finish: Option<String>,
    pub text: String,
    pub response_id: Option<String>,
    pub model: Option<String>,
    pub fingerprint: Option<String>,
    pub usage: Option<Value>,
    pub counts: BTreeMap<String, Option<i64>>,
    pub local_input: usize,
    pub local_output: usize,
    pub input_delta: Option<i64>,
    pub calls: Vec<Value>,
    pub output_items: Vec<Value>,
    pub cost: Option<f64>,
}
impl Row {
    pub fn new(seq: usize, probe: usize, label: &str, protocol: &str, body: Value) -> Self {
        let stream = body["stream"].as_bool().unwrap_or(false);
        Self {
            seq,
            probe,
            label: label.into(),
            protocol: protocol.into(),
            disguised: true,
            method: "POST".into(),
            path: String::new(),
            headers: json!({}),
            body,
            response_headers: json!({}),
            status: None,
            error: None,
            snippet: String::new(),
            elapsed: 0.,
            phases: json!({}),
            ttft: None,
            chunks: vec![],
            events: vec![],
            stream,
            complete: false,
            finish: None,
            text: String::new(),
            response_id: None,
            model: None,
            fingerprint: None,
            usage: None,
            counts: BTreeMap::new(),
            local_input: 0,
            local_output: 0,
            input_delta: None,
            calls: vec![],
            output_items: vec![],
            cost: None,
        }
    }
    pub fn ok(&self) -> bool {
        self.status == Some(200) && self.error.is_none() && self.complete
    }
    pub fn n(&self, key: &str) -> Option<i64> {
        self.counts.get(key).copied().flatten()
    }
    pub fn rate(&self) -> Option<f64> {
        crate::probes::ratio(
            self.n("cached").map(|v| v as f64),
            self.n("input").map(|v| v as f64),
        )
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: usize,
    pub name: String,
    pub status: String,
    pub strength: String,
    pub summary: String,
    pub samples: usize,
    pub evidence: Vec<usize>,
    pub metrics: Value,
    pub score: Option<f64>,
    pub hard: bool,
}
