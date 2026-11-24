use super::{security, tokenizer};
use crate::schemas::Profile;
use serde_json::{json, Value};
use std::{path::PathBuf, sync::Mutex};

pub fn tool(name: &str, description: &str, properties: Value) -> Value {
    let required: Vec<_> = properties.as_object().unwrap().keys().cloned().collect();
    json!({"type":"function","name":name,"description":description,"strict":true,
        "parameters":{"type":"object","properties":properties,"required":required,"additionalProperties":false}})
}
pub fn builtin() -> Profile {
    let mut p: Profile = serde_json::from_str(include_str!("../../assets/builtin.json")).unwrap();
    let mut body = p.body.clone();
    body["input"] = json!("");
    p.baseline_tokens = tokenizer::input_count(&body);
    p
}
pub struct Store {
    pub path: PathBuf,
    profiles: Mutex<Vec<Profile>>,
}
impl Store {
    pub fn new(path: PathBuf) -> Result<Self, String> {
        let profiles = if path.exists() {
            serde_json::from_slice(&std::fs::read(&path).map_err(|_| "Profile 文件读取失败")?)
                .map_err(|_| "Profile 文件格式无效")?
        } else {
            vec![]
        };
        Ok(Self {
            path,
            profiles: Mutex::new(profiles),
        })
    }
    pub fn all(&self) -> Vec<Profile> {
        let mut p = vec![builtin()];
        p.extend(self.profiles.lock().unwrap().clone());
        p
    }
    pub fn get(&self, id: &str) -> Option<Profile> {
        self.all().into_iter().find(|p| p.id == id)
    }
    fn write(&self, profiles: &[Profile]) -> Result<(), String> {
        let parent = self.path.parent().ok_or("Profile 路径无效")?;
        std::fs::create_dir_all(parent).map_err(|_| "Profile 目录无法写入")?;
        let temp = self.path.with_extension("tmp");
        std::fs::write(&temp, serde_json::to_vec_pretty(profiles).unwrap())
            .map_err(|_| "Profile 无法写入")?;
        std::fs::rename(temp, &self.path).map_err(|_| "Profile 无法替换")?;
        Ok(())
    }
    pub fn delete(&self, id: &str) -> Result<bool, String> {
        let mut lock = self.profiles.lock().unwrap();
        let mut next = lock.clone();
        next.retain(|p| p.id != id);
        if next.len() == lock.len() {
            return Ok(false);
        }
        self.write(&next)?;
        *lock = next;
        Ok(true)
    }
    pub fn save(&self, p: Profile, mut secrets: Vec<String>) -> Result<Profile, String> {
        if p.name.is_empty()
            || p.name.len() > 640
            || !p.body.is_object()
            || !["responses", "chat"].contains(&p.protocol.as_str())
            || !["自建基准模板", "实机抓包复刻", "原文导入"].contains(&p.source.as_str())
        {
            return Err("Profile 字段格式无效".into());
        }
        secrets.extend(security::auth_values(&json!(p)));
        let mut safe: Profile = serde_json::from_value(security::scrub(&json!(p), &secrets))
            .map_err(|_| "Profile 字段格式无效")?;
        safe.headers =
            serde_json::from_value(security::clean_headers(&json!(p.headers), &secrets)).unwrap();
        for k in [
            "session_id",
            "conversation_id",
            "x-session-id",
            "x-client-request-id",
        ] {
            if let Some(v) = safe.headers.get_mut(k) {
                *v = "{session}".into();
            }
        }
        for k in [
            "model",
            "previous_response_id",
            "prompt_cache_key",
            "metadata",
            "user",
            "safety_identifier",
        ] {
            safe.body.as_object_mut().unwrap().remove(k);
        }
        for k in ["input", "messages"] {
            if let Some(v) = safe.body.get_mut(k) {
                if let Some(a) = v.as_array_mut() {
                    a.retain(|m| m["role"] == "system" || m["role"] == "developer");
                } else {
                    *v = if k == "input" { json!("") } else { json!([]) };
                }
            }
        }
        if safe.id.is_empty() || safe.id == "builtin" {
            safe.id = uuid::Uuid::new_v4().simple().to_string();
        }
        let k = if safe.protocol == "chat" {
            "messages"
        } else {
            "input"
        };
        if safe.body.get(k).is_none() {
            safe.body[k] = if k == "input" { json!("") } else { json!([]) };
        }
        safe.baseline_tokens = tokenizer::input_count(&safe.body);
        let mut lock = self.profiles.lock().unwrap();
        let mut next = lock.clone();
        next.retain(|p| p.id != safe.id);
        next.push(safe.clone());
        self.write(&next)?;
        *lock = next;
        Ok(safe)
    }
}
pub fn parse_import(raw: Value, name: &str, protocol: Option<&str>) -> Result<Profile, String> {
    let mut headers = json!({});
    let mut name = name.to_owned();
    let body;
    if let Some(s) = raw.as_str().filter(|s| s.trim_start().starts_with("curl ")) {
        let words = shell_words::split(&s.replace("\\\r\n", "").replace("\\\n", ""))
            .map_err(|_| "cURL 格式无效")?;
        let mut args = words.iter();
        let mut found = None;
        while let Some(arg) = args.next() {
            if ["-H", "--header"].contains(&arg.as_str()) {
                if let Some((k, v)) = args.next().and_then(|s| s.split_once(':')) {
                    headers[k.trim()] = json!(v.trim());
                }
            } else if ["-d", "--data", "--data-raw", "--data-binary", "--json"]
                .contains(&arg.as_str())
            {
                found = Some(
                    serde_json::from_str::<Value>(args.next().ok_or("cURL 缺少请求体")?)
                        .map_err(|_| "cURL JSON 无效")?,
                );
            }
        }
        body = found.ok_or("cURL 需要内联 JSON 请求体")?;
    } else {
        let obj = if let Some(s) = raw.as_str() {
            serde_json::from_str(s).map_err(|_| "JSON 格式无效")?
        } else {
            raw
        };
        if obj.get("body").is_some() {
            headers = obj.get("headers").cloned().unwrap_or(json!({}));
            if let Some(n) = obj["name"].as_str() {
                name = n.into();
            }
            body = obj["body"].clone();
        } else {
            body = obj;
        }
    }
    if !body.is_object() {
        return Err("Profile body 需要对象".into());
    }
    let headers: std::collections::BTreeMap<String, String> =
        serde_json::from_value(headers).map_err(|_| "请求头格式无效")?;
    let client = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
        .map(|(_, v)| v.clone())
        .unwrap_or("原文导入".into());
    Ok(Profile {
        id: String::new(),
        name,
        client,
        source: "原文导入".into(),
        protocol: protocol
            .unwrap_or(if body.get("messages").is_some() {
                "chat"
            } else {
                "responses"
            })
            .into(),
        headers,
        body,
        baseline_tokens: 0,
    })
}
