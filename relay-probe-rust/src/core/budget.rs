use super::tokenizer::input_count;
use crate::schemas::{Prices, Row, Spec};
use serde_json::{json, Value};
pub fn cost(
    p: Option<&Prices>,
    i: Option<i64>,
    o: Option<i64>,
    cached: Option<i64>,
) -> Option<f64> {
    let (p, i, o, c) = (p?, i?, o?, cached?);
    if c > i {
        return None;
    }
    Some(((i - c) as f64 * p.input + c as f64 * p.cached + o as f64 * p.output) / 1e6)
}
pub struct Budget {
    spec: Spec,
    pub sent: usize,
    pub tokens: usize,
    pub reserved: usize,
    pub spent: f64,
    charged: f64,
    reserved_usd: f64,
    pub unknown: usize,
    pub limit: f64,
    pub stopped: String,
}
impl Budget {
    pub fn new(spec: &Spec) -> Self {
        Self {
            spec: spec.clone(),
            sent: 0,
            tokens: 0,
            reserved: 0,
            spent: 0.,
            charged: 0.,
            reserved_usd: 0.,
            unknown: 0,
            limit: spec
                .controls
                .budget_usd
                .unwrap_or(if spec.mode == "quick" { 1. } else { 2. }),
            stopped: String::new(),
        }
    }
    pub fn reserve(&mut self, body: &Value, aux: bool) -> Result<(usize, f64), String> {
        let i = if aux { 0 } else { input_count(body) };
        let o = body["max_output_tokens"]
            .as_u64()
            .or(body["max_completion_tokens"].as_u64())
            .unwrap_or(0) as usize;
        let tokens = i + o;
        let usd = self
            .spec
            .prices
            .as_ref()
            .map(|p| (i as f64 * p.input.max(p.cached) + o as f64 * p.output) / 1e6)
            .unwrap_or(0.);
        if self.stopped.is_empty() {
            if self.spec.prices.is_some() && self.charged + self.reserved_usd + usd > self.limit {
                self.stopped = "因预算熔断提前结束，样本不完整".into();
            } else if self.spec.prices.is_none()
                && (self.sent >= self.spec.controls.max_requests
                    || self.tokens + self.reserved + tokens > self.spec.controls.max_tokens)
            {
                self.stopped = "因最大请求数或最大总 token 数物理熔断提前结束，样本不完整".into();
            }
        }
        if !self.stopped.is_empty() {
            return Err(self.stopped.clone());
        }
        self.sent += 1;
        self.reserved += tokens;
        self.reserved_usd += usd;
        Ok((tokens, usd))
    }
    pub fn settle(&mut self, (tokens, usd): (usize, f64), row: &mut Row, aux: bool) {
        self.reserved -= tokens;
        self.reserved_usd -= usd;
        self.tokens += row.n("input").unwrap_or(row.local_input as i64) as usize
            + row
                .n("output")
                .unwrap_or(row.local_output.max(tokens.saturating_sub(row.local_input)) as i64)
                as usize;
        row.cost = if aux && self.spec.prices.is_some() {
            Some(0.)
        } else {
            cost(
                self.spec.prices.as_ref(),
                row.n("input"),
                row.n("output"),
                row.n("cached"),
            )
        };
        if self.spec.prices.is_some() && row.cost.is_none() {
            self.unknown += 1;
        }
        self.spent += row.cost.unwrap_or(0.);
        self.charged += row.cost.unwrap_or(usd);
    }
    pub fn snapshot(&self) -> Value {
        json!({"sent":self.sent,"tokens":self.tokens,"cost":self.spec.prices.as_ref().map(|_|self.spent),
            "unknown_cost":self.unknown,"budget":self.limit,"reserved":self.reserved})
    }
}
