use super::tokenizer::count;
use crate::schemas::{Profile, Row};
use serde_json::{json, Value};

#[derive(Clone)]
pub struct Options {
    pub cancel: Option<tokio_util::sync::CancellationToken>,
    pub bare: Option<bool>,
    pub key: Option<String>,
    pub session: String,
    pub heavy: bool,
    pub track_failure: bool,
    pub system: String,
    pub stream: bool,
    pub effort: Option<String>,
    pub limit: usize,
    pub tools: Option<Value>,
    pub forced: Option<String>,
    pub schema: Option<Value>,
    pub extra: Value,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            cancel: None,
            bare: None,
            key: None,
            session: String::new(),
            heavy: false,
            track_failure: true,
            system: String::new(),
            stream: true,
            effort: None,
            limit: 256,
            tools: None,
            forced: None,
            schema: None,
            extra: json!({}),
        }
    }
}
pub fn path(protocol: &str) -> &str {
    if protocol == "chat" {
        "/v1/chat/completions"
    } else {
        "/v1/responses"
    }
}
pub fn downgrade(status: Option<u16>, snippet: &str) -> bool {
    match status {
        Some(404 | 405 | 501) => true,
        None | Some(401 | 403 | 429) => false,
        Some(s) if s >= 500 => false,
        _ => ["endpoint unsupported", "not implemented", "unknown path"]
            .iter()
            .any(|x| snippet.to_lowercase().contains(x)),
    }
}
fn chat_tool(t: &Value) -> Value {
    if t["type"] == "function" && t.get("name").is_some() {
        let mut f = t.clone();
        f.as_object_mut().unwrap().remove("type");
        json!({"type":"function","function":f})
    } else {
        t.clone()
    }
}
fn chat_message(item: &Value) -> Value {
    match item["type"].as_str() {
        Some("function_call") => json!({"role":"assistant","content":null,"tool_calls":[{
            "id":item["call_id"],"type":"function","function":{"name":item["name"],"arguments":item["arguments"]}}]}),
        Some("function_call_output") => {
            json!({"role":"tool","tool_call_id":item["call_id"],"content":item["output"]})
        }
        _ => {
            let mut msg = item.clone();
            if let Some(parts) = item["content"].as_array() {
                msg["content"] = Value::Array(
                    parts
                        .iter()
                        .map(|p| match p["type"].as_str() {
                            Some("input_image") => {
                                json!({"type":"image_url","image_url":{"url":p["image_url"]}})
                            }
                            Some("input_text") => json!({"type":"text","text":p["text"]}),
                            _ => p.clone(),
                        })
                        .collect(),
                );
            }
            msg
        }
    }
}
pub fn build(
    protocol: &str,
    model: &str,
    profile: &Profile,
    prompt: Value,
    cache_key: &str,
    bare: bool,
    o: &Options,
) -> Value {
    let mut b = if bare {
        json!({})
    } else {
        profile.body.clone()
    };
    let map = b.as_object_mut().unwrap();
    let mut fixed = vec![];
    for k in ["input", "messages"] {
        if let Some(Value::Array(items)) = map.remove(k) {
            fixed.extend(items);
        }
    }
    let simple = prompt.is_string();
    let items = if simple {
        vec![json!({"role":"user","content":prompt})]
    } else {
        prompt.as_array().cloned().unwrap_or_default()
    };
    let mut inst = map
        .remove("instructions")
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    if !o.system.is_empty() {
        if !inst.is_empty() {
            inst.push('\n');
        }
        inst.push_str(&o.system);
    }
    if let Some(t) = &o.tools {
        b["tools"] = t.clone();
    }
    if let Some(f) = &o.forced {
        b["tool_choice"] = json!({"type":"function","name":f});
    }
    b["model"] = json!(model);
    b["stream"] = json!(o.stream);
    if !bare {
        b["prompt_cache_key"] = json!(cache_key);
    }
    let mut reasoning = b
        .as_object_mut()
        .unwrap()
        .remove("reasoning")
        .unwrap_or(json!({}));
    let base = b.as_object_mut().unwrap().remove("reasoning_effort");
    if let Some(e) = &o.effort {
        reasoning["effort"] = json!(e);
    } else if let Some(e) = base {
        reasoning["effort"] = e;
    }
    if protocol == "responses" {
        if !inst.is_empty() {
            b["instructions"] = json!(inst);
        }
        b["input"] = if fixed.is_empty() && simple {
            prompt
        } else {
            fixed.extend(items);
            json!(fixed)
        };
        for k in ["stream_options", "max_completion_tokens"] {
            b.as_object_mut().unwrap().remove(k);
        }
        if reasoning.as_object().is_some_and(|m| !m.is_empty()) {
            b["reasoning"] = reasoning;
        }
        if let Some(tools) = b["tools"].as_array() {
            b["tools"] = json!(tools
                .iter()
                .map(|t| {
                    if t["type"] == "function" && t["function"].is_object() {
                        let mut v = json!({"type":"function"});
                        v.as_object_mut()
                            .unwrap()
                            .extend(t["function"].as_object().unwrap().clone());
                        v
                    } else {
                        t.clone()
                    }
                })
                .collect::<Vec<_>>());
        }
        if b["tool_choice"]["function"].is_object() {
            b["tool_choice"] =
                json!({"type":"function","name":b["tool_choice"]["function"]["name"]});
        }
        if let Some(schema) = &o.schema {
            let mut format = json!({"type":"json_schema"});
            format
                .as_object_mut()
                .unwrap()
                .extend(schema.as_object().unwrap().clone());
            b["text"] = json!({"format":format});
        }
        b["max_output_tokens"] = json!(o.limit);
    } else {
        for k in [
            "include",
            "previous_response_id",
            "text",
            "max_output_tokens",
            "truncation",
        ] {
            b.as_object_mut().unwrap().remove(k);
        }
        let mut messages = vec![];
        if !inst.is_empty() {
            messages.push(json!({"role":"system","content":inst}));
        }
        fixed.extend(items);
        messages.extend(fixed.iter().map(chat_message));
        b["messages"] = json!(messages);
        if let Some(e) = reasoning.get("effort") {
            b["reasoning_effort"] = e.clone();
        }
        if let Some(tools) = b["tools"].as_array() {
            b["tools"] = json!(tools
                .iter()
                .filter(|t| t["type"] == "function")
                .map(chat_tool)
                .collect::<Vec<_>>());
        }
        if b["tool_choice"].is_object() {
            b["tool_choice"] = chat_tool(&b["tool_choice"]);
        }
        if let Some(s) = &o.schema {
            b["response_format"] = json!({"type":"json_schema","json_schema":s});
        }
        if o.stream {
            b["stream_options"] = json!({"include_usage":true});
        } else {
            b.as_object_mut().unwrap().remove("stream_options");
        }
        b["max_completion_tokens"] = json!(o.limit);
    }
    if let Some(extra) = o.extra.as_object() {
        b.as_object_mut().unwrap().extend(extra.clone());
    }
    b
}
pub fn counts(row: &mut Row) {
    let u = row.usage.clone().unwrap_or(Value::Null);
    let (i, o) = if row.protocol == "chat" {
        ("prompt_tokens", "completion_tokens")
    } else {
        ("input_tokens", "output_tokens")
    };
    for (k, v) in [
        ("input", &u[i]),
        ("output", &u[o]),
        ("cached", &u[format!("{i}_details")]["cached_tokens"]),
        ("reasoning", &u[format!("{o}_details")]["reasoning_tokens"]),
        ("total", &u["total_tokens"]),
    ] {
        row.counts.insert(k.into(), v.as_i64().filter(|v| *v >= 0));
    }
}
fn call_mut(row: &mut Row, index: usize) -> &mut Value {
    let position = row
        .calls
        .iter()
        .position(|v| v["index"].as_u64() == Some(index as u64))
        .unwrap_or_else(|| {
            row.calls
                .push(json!({"index":index,"name":"","call_id":"","arguments":""}));
            row.calls.len() - 1
        });
    &mut row.calls[position]
}
fn append(v: &mut Value, key: &str, s: &str) {
    v[key] = json!(format!("{}{}", v[key].as_str().unwrap_or(""), s));
}
pub fn absorb(row: &mut Row, obj: &Value, event: &str, elapsed: f64) {
    if !obj.is_object() {
        return;
    }
    let mut delta = String::new();
    let data;
    if row.protocol == "responses" {
        let typ = obj["type"].as_str().unwrap_or(event);
        data = obj.get("response").unwrap_or(obj);
        match typ {
            "response.output_text.delta" => {
                delta = obj["delta"].as_str().unwrap_or("").into();
                row.text.push_str(&delta);
            }
            "response.function_call_arguments.delta" => {
                delta = obj["delta"].as_str().unwrap_or("").into();
                append(
                    call_mut(row, obj["output_index"].as_u64().unwrap_or(0) as usize),
                    "arguments",
                    &delta,
                );
            }
            "response.output_item.added" | "response.output_item.done" => {
                let item = &obj["item"];
                if typ.ends_with(".done") && item.is_object() {
                    row.output_items.push(item.clone());
                }
                if item["type"] == "function_call" {
                    let c = call_mut(row, obj["output_index"].as_u64().unwrap_or(0) as usize);
                    for k in ["name", "call_id"] {
                        if item[k].is_string() {
                            c[k] = item[k].clone();
                        }
                    }
                    if item["arguments"].as_str().is_some_and(|s| !s.is_empty()) {
                        c["arguments"] = item["arguments"].clone();
                    }
                }
            }
            "response.failed" | "error" => {
                row.error = Some("SSE 上游错误".into());
                row.snippet = data["error"].to_string();
            }
            _ => {}
        }
        if ["response.completed", "response.incomplete"].contains(&typ) || !row.stream {
            let finish = data["status"].as_str().unwrap_or(typ).to_owned();
            row.complete = ["completed", "response.completed"].contains(&finish.as_str());
            row.finish = Some(finish);
            if let Some(items) = data["output"].as_array() {
                row.output_items = items.clone();
            }
            if row.text.is_empty() && (!row.stream || row.chunks.is_empty()) {
                for item in &row.output_items {
                    if let Some(parts) = item["content"].as_array() {
                        for p in parts {
                            if p["type"] == "output_text" {
                                row.text.push_str(p["text"].as_str().unwrap_or(""));
                            }
                        }
                    }
                }
            }
            if row.calls.is_empty() {
                for (ix, item) in row.output_items.iter().enumerate() {
                    if item["type"] == "function_call" {
                        row.calls.push(json!({"index":ix,"name":item["name"],"call_id":item["call_id"],"arguments":item["arguments"]}));
                    }
                }
            }
        }
    } else {
        data = obj;
        if let Some(choices) = obj["choices"].as_array() {
            for choice in choices {
                let msg = &choice[if row.stream { "delta" } else { "message" }];
                let piece = msg["content"].as_str().unwrap_or("");
                row.text.push_str(piece);
                delta.push_str(piece);
                if let Some(parts) = msg["tool_calls"].as_array() {
                    for (ix, p) in parts.iter().enumerate() {
                        let c = call_mut(row, p["index"].as_u64().unwrap_or(ix as u64) as usize);
                        append(c, "call_id", p["id"].as_str().unwrap_or(""));
                        append(c, "name", p["function"]["name"].as_str().unwrap_or(""));
                        let args = p["function"]["arguments"].as_str().unwrap_or("");
                        append(c, "arguments", args);
                        delta.push_str(args);
                    }
                }
                if let Some(f) = choice["finish_reason"].as_str() {
                    row.finish = Some(f.into());
                    if !row.stream {
                        row.complete = true;
                    }
                }
            }
        }
    }
    if !delta.is_empty() && row.stream {
        row.ttft.get_or_insert(elapsed);
        row.chunks
            .push(json!({"t":elapsed,"tokens":count(&delta),"chars":delta.chars().count()}));
    }
    if let Some(s) = data["id"].as_str() {
        row.response_id = Some(s.into());
    }
    if let Some(s) = data["model"].as_str() {
        row.model = Some(s.into());
    }
    if let Some(s) = data["system_fingerprint"].as_str() {
        row.fingerprint = Some(s.into());
    }
    if data["usage"].is_object() {
        row.usage = Some(data["usage"].clone());
    }
}
