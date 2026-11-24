use super::scoring_probes::{lookup_tool, valid_call};
use super::{nonce, Probe};
use crate::{
    core::{profiles::tool, protocols::Options, tokenizer::padding},
    schemas::Finding,
};
use serde_json::{json, Value};
pub async fn execute(c: &Probe<'_>) -> Result<Finding, String> {
    match c.id {
        28 => encrypted(c).await,
        29 => escaping(c).await,
        30 => echo(c).await,
        31 => parameters(c).await,
        32 => truncation(c).await,
        33 => memory(c).await,
        34 => benign_terms(c).await,
        35 => vision(c).await,
        36 => context(c).await,
        _ => unreachable!(),
    }
}
async fn encrypted(c: &Probe<'_>) -> Result<Finding, String> {
    if c.run.protocol() != "responses" {
        return Ok(c.lack(
            "当前为 Chat Completions，该项需要 Responses",
            json!({}),
            None,
        ));
    }
    let first = json!({"role":"user","content":format!("校核任务 {}。计算 37 × 19，再用一句话解释。",c.run.salt)});
    let opts = Options {
        effort: Some("high".into()),
        heavy: true,
        extra: json!({"store":false,"include":["reasoning.encrypted_content"]}),
        ..Default::default()
    };
    let a = c
        .ask("首轮加密推理项", json!([first]), opts.clone())
        .await?;
    let items = a
        .output_items
        .iter()
        .filter(|i| {
            i["type"] == "reasoning"
                && i["encrypted_content"]
                    .as_str()
                    .is_some_and(|s| !s.is_empty())
        })
        .count();
    if !a.ok() || items == 0 {
        return Ok(c.finding(
            format!("首轮返回 {items} 个可回传的加密推理项"),
            json!({"count":items}),
            None,
            "需关注",
            None,
            false,
        ));
    }
    let mut history = vec![first];
    history.extend(a.output_items);
    history.push(json!({"role":"user","content":"根据刚才的计算只回复结果。"}));
    let b = c.ask("原样回传加密项", json!(history), opts).await?;
    Ok(c.finding(
        format!("{items} 个推理项原样回传，二轮 HTTP {:?}", b.status),
        json!({"items":items,"second_status":b.status}),
        None,
        if b.ok() { "通过" } else { "异常" },
        None,
        false,
    ))
}
async fn escaping(c: &Probe<'_>) -> Result<Finding, String> {
    let patch=format!("函数 patch_{}():\n    # 中文注释 \"保留引号\"\n    if ready:\n        emit(\"C:\\\\日志\\\\文件\\n\", '嵌套 \"字符\"')\n",&c.run.salt[..6]);
    let t = tool(
        "record_patch",
        "逐字符记录补丁。",
        json!({"patch":{"type":"string"}}),
    );
    let r = c
        .ask(
            "流式参数拼接",
            format!("调用 record_patch，把以下文本原样传入：\n{patch}"),
            Options {
                tools: Some(json!([t])),
                forced: Some("record_patch".into()),
                ..Default::default()
            },
        )
        .await?;
    let value = r
        .calls
        .first()
        .and_then(|c| c["arguments"].as_str())
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v["patch"].as_str().map(str::to_owned));
    let streamed = if c.run.protocol() == "responses" {
        r.events
            .iter()
            .any(|e| e == "response.function_call_arguments.delta")
    } else {
        !r.chunks.is_empty()
    };
    Ok(c.checked(
        json!({"流式参数到达":streamed,"解码后逐字一致":r.ok()&&value.as_ref()==Some(&patch)}),
        json!({"expected":patch,"actual":value}),
        false,
    ))
}
async fn echo(c: &Probe<'_>) -> Result<Finding, String> {
    let value = format!("墨/{}+Ω=尾", &nonce()[..20]);
    let r = c
        .ask(
            "随机串回声",
            format!("原样回显【{value}】，不加任何文字。"),
            Options::default(),
        )
        .await?;
    Ok(c.checked(
        json!({"原样回显":r.ok()&&r.text==value}),
        json!({"expected":value,"actual":r.text}),
        false,
    ))
}
async fn parameters(c: &Probe<'_>) -> Result<Finding, String> {
    let value = format!("A{}", &c.run.salt[..8]);
    let prompt = format!("原样回显【{value}】，只输出括号中的内容。");
    let options = Options {
        extra: json!({"temperature":0}),
        ..Default::default()
    };
    let a = c
        .ask("temperature=0 第一次", prompt.clone(), options.clone())
        .await?;
    let b = c.ask("temperature=0 第二次", prompt, options).await?;
    let lim = c
        .ask(
            "输出上限 8 tok",
            "连续输出 500 次字符 X。",
            Options {
                limit: 8,
                effort: Some("low".into()),
                ..Default::default()
            },
        )
        .await?;
    let stop = format!("§{}", c.run.salt);
    let s = c
        .ask(
            "stop 序列",
            format!("原样回显【{value}{stop}after】"),
            Options {
                extra: json!({"stop":[stop]}),
                ..Default::default()
            },
        )
        .await?;
    let f = c
        .ask(
            "强制工具",
            "调用 lookup_value 函数，key 取 value。",
            Options {
                tools: Some(json!([lookup_tool("lookup_value")])),
                forced: Some("lookup_value".into()),
                ..Default::default()
            },
        )
        .await?;
    let mut statuses = json!({});
    for r in c.rows() {
        statuses[&r.label] = json!(r.status);
    }
    Ok(c.checked(json!({"temperature=0 一致":a.ok()&&b.ok()&&a.text==b.text&&a.text==value,
        "输出上限":lim.status==Some(200)&&lim.n("output").is_some_and(|n|n<=8),
        "stop 生效":s.ok()&&s.text==value,"forced tool":f.ok()&&f.calls.len()==1&&valid_call(&f.calls[0],"lookup_value")}),
        json!({"parameter_status":statuses}),false))
}
async fn truncation(c: &Probe<'_>) -> Result<Finding, String> {
    let mut checks = json!({});
    let mut rows = vec![];
    for stream in [true, false] {
        let r = c
            .ask(
                if stream { "流式" } else { "非流式" },
                "连续输出 128 次字符 X，只返回这一行。",
                Options {
                    stream,
                    ..Default::default()
                },
            )
            .await?;
        checks[&r.label] = json!(r.ok() && r.text == "X".repeat(128));
        rows.push(
            json!({"seq":r.seq,"length":r.text.chars().count(),"finish_reason_or_status":r.finish}),
        );
    }
    Ok(c.checked(checks, json!({"rows":rows}), false))
}
async fn memory(c: &Probe<'_>) -> Result<Finding, String> {
    let mut facts = json!({});
    let mut text = String::new();
    for k in ["river", "key", "tree"] {
        let v = nonce()[..10].to_owned();
        facts[k] = json!(v);
        text.push_str(&format!("事实 {k}={v}\n"));
    }
    let mut history = vec![json!({"role":"user","content":text+"记住三项后回复 OK。"})];
    let first = c
        .ask("建立三项事实", json!(history), Options::default())
        .await?;
    history.push(json!({"role":"assistant","content":first.text}));
    let mut checks = json!({});
    for (k, v) in facts.as_object().unwrap() {
        history.push(json!({"role":"user","content":format!("查询 {k}，只回复事实值。")}));
        let r = c
            .ask(&format!("回忆 {k}"), json!(history), Options::default())
            .await?;
        checks[k] = json!(r.ok() && Some(r.text.trim()) == v.as_str());
        history.push(json!({"role":"assistant","content":r.text}));
    }
    Ok(c.checked(checks, json!({"facts":facts}), false))
}
async fn benign_terms(c: &Probe<'_>) -> Result<Finding, String> {
    let prompts = [
        "说明代码审查中将 rm -rf 标作危险命令的原因。",
        "用一句话描述 eval 的安全审计目的。",
        "说明参数化查询如何防御 SQL 拼接风险。",
        "说明为何文档中用虚构占位符 sk-test-0000。",
    ];
    for (i, p) in prompts.iter().enumerate() {
        match c
            .ask(&format!("无害审计词 {}", i + 1), *p, Options::default())
            .await
        {
            Ok(_) => {}
            Err(e) if e.contains("连续失败") => break,
            Err(e) => return Err(e),
        }
    }
    let rows = c.rows();
    let mut checks = json!({});
    for (name, r) in ["rm -rf", "eval", "SQL", "测试占位符"].iter().zip(&rows) {
        checks[*name] = json!(r.ok());
    }
    Ok(c.checked(
        checks,
        json!({"statuses":rows.iter().map(|r|r.status).collect::<Vec<_>>(),"untested":4-rows.len(),
        "scope":if rows.len()<4{"连续失败后未发出的样本证据不足"}else{"全部词项已采样"}}),
        false,
    ))
}
async fn vision(c: &Probe<'_>) -> Result<Finding, String> {
    use base64::Engine;
    use rand::Rng;
    let ix = rand::thread_rng().gen_range(0..3);
    let (color, rgb) = [
        ("红", [255, 0, 0]),
        ("绿", [0, 255, 0]),
        ("蓝", [0, 0, 255]),
    ][ix];
    let mut bytes = vec![];
    {
        let mut encoder = png::Encoder::new(&mut bytes, 16, 16);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().map_err(|_| "PNG 图像编码失败")?;
        writer
            .write_image_data(&rgb.repeat(256))
            .map_err(|_| "PNG 图像编码失败")?;
    }
    let image = format!(
        "data:image/png;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    );
    let prompt = json!([{"role":"user","content":[{"type":"input_text","text":"这张图是什么颜色？只答红、绿、蓝中的一个字。"},{"type":"input_image","image_url":image}]}]);
    let r = c.ask("随机纯色 PNG", prompt, Options::default()).await?;
    Ok(c.checked(
        json!({"颜色相符":r.ok()&&r.text.trim()==color}),
        json!({"expected":color,"actual":r.text}),
        false,
    ))
}
async fn context(c: &Probe<'_>) -> Result<Finding, String> {
    let mut table = vec![];
    for n in [32000, 64000, 128000, 200000] {
        let code = nonce()[..14].to_owned();
        let prompt = format!(
            "校验码={code}\n{}\n只返回校验码，不要解释。",
            padding(n, &format!("{}{n}", c.run.salt))
        );
        let r = c
            .ask(
                &format!("{}K 档", n / 1000),
                prompt,
                Options {
                    heavy: true,
                    ..Default::default()
                },
            )
            .await?;
        table.push(json!({"padding":n,"local_input":r.local_input,"status":r.status,"recalled":r.ok()&&r.text.trim()==code,"seq":r.seq}));
        c.set("context_steps", json!(table));
    }
    let passed: Vec<_> = table
        .iter()
        .filter(|r| r["recalled"] == true)
        .filter_map(|r| r["local_input"].as_u64())
        .collect();
    Ok(c.finding(
        format!("4 档中 {} 档通过头部随机码校验", passed.len()),
        json!({"steps":table,"highest_verified":passed.iter().max()}),
        None,
        if passed.len() == 4 {
            "通过"
        } else {
            "需关注"
        },
        None,
        false,
    ))
}
