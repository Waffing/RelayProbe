use super::{
    budget::Budget,
    client::Relay,
    protocols::{self, Options},
    tokenizer,
};
use crate::{
    probes::{self, Probe},
    schemas::{Finding, Profile, Row, Spec},
};
use chrono::Local;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

pub struct Data {
    pub rows: Vec<Row>,
    pub findings: BTreeMap<usize, Finding>,
    pub memo: BTreeMap<String, Value>,
    pub budget: Budget,
    pub failures: BTreeMap<usize, usize>,
    pub events: Vec<(String, Value)>,
    pub finished: Option<Instant>,
    pub stop: String,
}
pub struct Run {
    pub id: String,
    pub salt: String,
    pub spec: Spec,
    pub profile: Profile,
    pub relay: Relay,
    pub ids: Vec<usize>,
    pub started: String,
    pub protocol: Mutex<String>,
    pub data: Mutex<Data>,
    pub changed: Notify,
    pub cancel: CancellationToken,
}
impl Run {
    pub fn new(spec: Spec, profile: Profile, relay: Relay) -> Arc<Self> {
        Arc::new(Self {
            id: probes::nonce(),
            salt: probes::nonce()[..20].into(),
            ids: probes::selected(&spec),
            started: Local::now().to_rfc3339(),
            protocol: Mutex::new(
                if spec.protocol == "chat" {
                    "chat"
                } else {
                    "responses"
                }
                .into(),
            ),
            data: Mutex::new(Data {
                rows: vec![],
                findings: BTreeMap::new(),
                memo: BTreeMap::new(),
                budget: Budget::new(&spec),
                failures: BTreeMap::new(),
                events: vec![],
                finished: None,
                stop: String::new(),
            }),
            spec,
            profile,
            relay,
            changed: Notify::new(),
            cancel: CancellationToken::new(),
        })
    }
    pub fn protocol(&self) -> String {
        self.protocol.lock().unwrap().clone()
    }
    pub fn rows(&self) -> Vec<Row> {
        self.data.lock().unwrap().rows.clone()
    }
    pub fn emit(&self, event: &str, data: Value) {
        self.data.lock().unwrap().events.push((event.into(), data));
        self.changed.notify_waiters();
    }
    pub fn log(&self, message: impl Into<String>, probe: usize) {
        self.emit(
            "log",
            json!({"time":Local::now().to_rfc3339(),"message":message.into(),"probe":probe}),
        );
    }
    async fn dispatch(
        &self,
        mut row: Row,
        headers: Value,
        read: f64,
        cancel: CancellationToken,
    ) -> Result<(Row, Value), String> {
        if self.cancel.is_cancelled() {
            return Err("手动中止，样本不完整".into());
        }
        let aux = row.method == "GET";
        let reservation;
        {
            let mut d = self.data.lock().unwrap();
            reservation = d.budget.reserve(&row.body, aux)?;
            row.seq = d.budget.sent;
        }
        row.local_input = if aux {
            0
        } else {
            tokenizer::input_count(&row.body)
        };
        let (mut row, data) = self.relay.exchange(row, headers, read, cancel).await;
        let sample;
        {
            let mut d = self.data.lock().unwrap();
            d.budget.settle(reservation, &mut row, aux);
            sample = {
                let mut v = d.budget.snapshot();
                for (k,val) in json!({"seq":row.seq,"probe":row.probe,"label":row.label,"status":row.status,"error":row.error,"elapsed":row.elapsed}).as_object().unwrap(){
                    v[k]=val.clone();
                }
                v
            };
            d.rows.push(row.clone());
        }
        self.emit("sample", sample);
        if self.cancel.is_cancelled() {
            return Err("手动中止，样本不完整".into());
        }
        Ok((row, data))
    }
    pub async fn ask(
        &self,
        pid: usize,
        label: &str,
        prompt: Value,
        opts: Options,
    ) -> Result<Row, String> {
        if opts.track_failure
            && self
                .data
                .lock()
                .unwrap()
                .failures
                .get(&pid)
                .copied()
                .unwrap_or(0)
                >= self.spec.controls.consecutive_failures
        {
            return Err("连续失败达到已配上限，证据不足".into());
        }
        let bare = opts.bare.unwrap_or(self.spec.bare);
        let protocol = self.protocol();
        let mut headers = json!({});
        if !bare {
            for (k, v) in &self.profile.headers {
                headers[k] = json!(v.replace("{session}", &(self.id.clone() + &opts.session)));
            }
        }
        let key = format!(
            "{}-{}",
            self.salt,
            opts.key.clone().unwrap_or(pid.to_string())
        );
        let mut body = protocols::build(
            &protocol,
            &self.spec.model,
            &self.profile,
            prompt,
            &key,
            bare,
            &opts,
        );
        if opts.key.is_some() {
            body["prompt_cache_key"] = json!(key);
        }
        let mut row = Row::new(0, pid, label, &protocol, body);
        row.disguised = !bare;
        row.path = protocols::path(&protocol).into();
        let read = if opts.heavy {
            self.spec.controls.heavy_s
        } else {
            self.spec.controls.read_s
        };
        let (row, _) = self
            .dispatch(
                row,
                headers,
                read,
                opts.cancel.unwrap_or_else(|| self.cancel.clone()),
            )
            .await?;
        if opts.track_failure {
            let mut d = self.data.lock().unwrap();
            let n = d.failures.entry(pid).or_insert(0);
            *n = if row.ok() { 0 } else { *n + 1 };
            if pid > 0 && *n >= self.spec.controls.consecutive_failures {
                return Err("连续失败达到已配上限，证据不足".into());
            }
        }
        Ok(row)
    }
    pub async fn aux(&self, pid: usize, label: &str, path: &str) -> Result<(Row, Value), String> {
        let mut row = Row::new(0, pid, label, &self.protocol(), json!({}));
        row.method = "GET".into();
        row.disguised = false;
        row.path = path.into();
        self.dispatch(
            row,
            json!({}),
            self.spec.controls.read_s,
            self.cancel.clone(),
        )
        .await
    }
    pub async fn wait(&self, seconds: f64) -> Result<(), String> {
        tokio::select! {_ = self.cancel.cancelled()=>Err("手动中止，样本不完整".into()),
        _=tokio::time::sleep(std::time::Duration::from_secs_f64(seconds))=>Ok(())}
    }
    async fn work(&self) -> Result<(), String> {
        self.log("已创建任务，开始协议预检", 0);
        if self.ids.contains(&15) {
            let c = Probe::new(self, 15);
            c.set(
                "balance_before",
                probes::billing_probes::balance_snapshot(&c, "整轮测前余额").await?,
            );
        }
        let opts = Options {
            track_failure: false,
            limit: 64,
            ..Default::default()
        };
        let mut pre = self
            .ask(0, "协议预检", json!("只回复 OK。"), opts.clone())
            .await?;
        if self.spec.protocol == "auto" && protocols::downgrade(pre.status, &pre.snippet) {
            *self.protocol.lock().unwrap() = "chat".into();
            self.log(
                format!(
                    "Responses HTTP {:?} 符合降级条件，切换 Chat Completions",
                    pre.status
                ),
                0,
            );
            pre = self
                .ask(0, "Chat 降级预检", json!("只回复 OK。"), opts)
                .await?;
        }
        if !pre.ok() {
            return Err(format!(
                "协议预检停止，{} {}",
                pre.error
                    .unwrap_or(pre.finish.unwrap_or("未正常完成".into())),
                pre.snippet.chars().take(220).collect::<String>()
            ));
        }
        if self.ids.contains(&24) {
            probes::signatures::checkpoint(&Probe::new(self, 24), "开头").await?;
        }
        let jobs: Vec<_> = self
            .ids
            .iter()
            .copied()
            .filter(|i| probes::active(*i))
            .collect();
        for (index, id) in jobs.iter().enumerate() {
            if self.ids.contains(&24) && index == jobs.len() / 2 {
                probes::signatures::checkpoint(&Probe::new(self, 24), "中段").await?;
            }
            let c = Probe::new(self, *id);
            self.log(probes::name(*id), *id);
            let outcome = if (37..=39).contains(id) && !c.memo("stress").is_null() {
                Ok(probes::stress_probes::result(&c))
            } else {
                probes::execute(&c).await
            };
            let result = match outcome {
                Ok(f) => f,
                Err(e) if e.contains("连续失败") => c.lack(e, json!({}), None),
                Err(e) => return Err(e),
            };
            self.data.lock().unwrap().findings.insert(*id, result);
            let mut progress = self.data.lock().unwrap().budget.snapshot();
            progress["probe"] = json!(id);
            progress["done"] = json!(index + 1);
            progress["total"] = json!(jobs.len());
            self.emit("progress", progress);
        }
        if self.ids.contains(&24) {
            if jobs.is_empty() {
                probes::signatures::checkpoint(&Probe::new(self, 24), "中段").await?;
            }
            probes::signatures::checkpoint(&Probe::new(self, 24), "末尾").await?;
        }
        if self.ids.contains(&15) {
            let c = Probe::new(self, 15);
            c.set(
                "balance_after",
                probes::billing_probes::balance_snapshot(&c, "整轮测后余额").await?,
            );
        }
        Ok(())
    }
    pub async fn execute(self: Arc<Self>) {
        use futures_util::FutureExt;
        let outcome = std::panic::AssertUnwindSafe(self.work())
            .catch_unwind()
            .await;
        let stop = match outcome {
            Ok(Ok(())) => String::new(),
            Ok(Err(e)) => e,
            Err(_) => "运行中断，样本不完整".into(),
        };
        self.data.lock().unwrap().stop = stop;
        self.relay.forget();
        for id in &self.ids {
            let c = Probe::new(&self, *id);
            let failures = self
                .data
                .lock()
                .unwrap()
                .failures
                .get(id)
                .copied()
                .unwrap_or(0);
            let prior = c.result(*id);
            let result = if prior.as_ref().is_some_and(|f| f.status == "证据不足") && failures > 0
            {
                prior
            } else {
                probes::passive(&c).or(prior)
            };
            let result = result.unwrap_or_else(|| {
                let stop = self.data.lock().unwrap().stop.clone();
                let metrics = if *id == 36 {
                    json!({"steps":c.memo("context_steps")})
                } else {
                    json!({})
                };
                c.lack(
                    if stop.is_empty() {
                        "未取得有效样本".into()
                    } else {
                        stop
                    },
                    metrics,
                    None,
                )
            });
            self.data.lock().unwrap().findings.insert(*id, result);
        }
        let report = super::scoring::report(&self);
        self.emit("report", report);
        self.data.lock().unwrap().finished = Some(Instant::now());
        self.changed.notify_waiters();
    }
    pub async fn abort(&self) {
        if self.data.lock().unwrap().finished.is_some() {
            return;
        }
        self.cancel.cancel();
        loop {
            let notified = self.changed.notified();
            if self.data.lock().unwrap().finished.is_some() {
                break;
            }
            notified.await;
        }
    }
}
