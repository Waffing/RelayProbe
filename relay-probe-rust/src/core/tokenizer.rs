use rand::{rngs::StdRng, Rng, SeedableRng};
use serde_json::{Map, Value};
use std::hash::{Hash, Hasher};
use std::sync::LazyLock;

static ENCODER: LazyLock<tiktoken_rs::CoreBPE> =
    LazyLock::new(|| tiktoken_rs::o200k_base().expect("embedded o200k_base"));
pub fn init() {
    LazyLock::force(&ENCODER);
}
pub fn count(text: &str) -> usize {
    ENCODER.encode_ordinary(text).len()
}
pub fn compact(value: &Value) -> String {
    serde_json::to_string(value).unwrap()
}
fn extract(value: &mut Value, tokens: &mut usize) {
    match value {
        Value::String(s) => {
            *tokens += count(s);
            s.clear();
        }
        Value::Array(a) => {
            for v in a {
                extract(v, tokens);
            }
        }
        Value::Object(m) => {
            for (k, v) in m {
                if k == "content" || k == "text" {
                    extract(v, tokens);
                }
            }
        }
        _ => {}
    }
}
pub fn input_count(body: &Value) -> usize {
    let mut skeleton = Map::new();
    let mut tokens = 0;
    for key in [
        "instructions",
        "input",
        "messages",
        "tools",
        "tool_choice",
        "text",
        "response_format",
    ] {
        if let Some(value) = body.get(key) {
            skeleton.insert(key.into(), value.clone());
        }
    }
    for key in ["input", "instructions", "messages"] {
        if let Some(value) = skeleton.get_mut(key) {
            extract(value, &mut tokens);
        }
    }
    tokens + count(&compact(&Value::Object(skeleton)))
}
pub fn padding(tokens: usize, salt: &str) -> String {
    if tokens == 0 {
        return String::new();
    }
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    salt.hash(&mut hasher);
    let mut rng = StdRng::seed_from_u64(hasher.finish());
    let words:Vec<_>=" amber ash atlas blue brass cedar clay cloud coral dawn delta dune fern field fog frost glass gold grain gray hill iron jade lake leaf lime map mint mist moon moss north oak orbit pearl pine plum pond rain reef ridge river rock rose ruby sand seed shore silk sky slate snow soft soil solar stone storm sun surf tide tree vale wave west wind wood zinc".split_whitespace().collect();
    let mut text = salt.to_owned();
    for _ in 0..tokens + 10 {
        text.push(' ');
        text.push_str(words[rng.gen_range(0..words.len())]);
    }
    let ids = ENCODER.encode_ordinary(&text);
    let value = ENCODER
        .decode(ids[..tokens].to_vec())
        .expect("ASCII padding");
    assert_eq!(count(&value), tokens);
    value
}
