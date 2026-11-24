use crate::{
    core::{
        client::Relay,
        profiles::{self, Store},
        runner::Run,
        security,
    },
    probes,
    schemas::{self, Profile, Spec},
};
use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, DefaultBodyLimit, Path, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{
        sse::{Event, KeepAlive},
        IntoResponse, Response, Sse,
    },
    routing::{delete, get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    convert::Infallible,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

struct Capture {
    token: Zeroizing<String>,
    until: Instant,
}
struct App {
    password: Zeroizing<String>,
    private: bool,
    store: Store,
    runs: Mutex<HashMap<String, Arc<Run>>>,
    capture: Mutex<Option<Capture>>,
    local_only: bool,
}
type Shared = Arc<App>;
type Failure = (StatusCode, Json<Value>);
fn fail(status: StatusCode, message: impl Into<String>) -> Failure {
    (status, Json(json!({"detail":message.into()})))
}
fn parse(bytes: &Bytes) -> Result<Value, Failure> {
    serde_json::from_slice(bytes)
        .map_err(|_| fail(StatusCode::UNPROCESSABLE_ENTITY, "JSON 输入格式无效"))
}
fn bearer(headers: &HeaderMap) -> &str {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once(' '))
        .filter(|(s, _)| s.eq_ignore_ascii_case("bearer"))
        .map(|(_, v)| v)
        .unwrap_or("")
}
const CAPTURE_PATHS: [&str; 2] = [
    "/api/capture/v1/responses",
    "/api/capture/v1/chat/completions",
];
async fn protect(State(app): State<Shared>, request: Request, next: Next) -> Response {
    let path = request.uri().path().to_owned();
    if path.starts_with("/api/") {
        let headers = request.headers();
        let host = headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if app.local_only {
            let hostname = url::Url::parse(&format!("http://{host}"))
                .ok()
                .and_then(|u| u.host_str().map(str::to_owned));
            if !hostname.is_some_and(|h| ["127.0.0.1", "localhost", "[::1]"].contains(&h.as_str()))
            {
                return fail(StatusCode::FORBIDDEN, "需要本机控制台地址").into_response();
            }
        }
        if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) {
            let origin_host = url::Url::parse(origin).ok().map(|u| {
                let host = u.host_str().unwrap_or("").to_owned();
                u.port().map(|p| format!("{host}:{p}")).unwrap_or(host)
            });
            if origin_host.as_deref() != Some(host) {
                return fail(StatusCode::FORBIDDEN, "需要同源控制台请求").into_response();
            }
        }
        if request.uri().query().is_some() {
            return fail(StatusCode::BAD_REQUEST, "API 参数仅接受请求体或请求头").into_response();
        }
        let token = bearer(headers);
        let capture_auth = CAPTURE_PATHS.contains(&path.as_str())
            && app.capture.lock().unwrap().as_ref().is_some_and(|c| {
                Instant::now() < c.until && security::authenticated(token, &c.token)
            });
        let password_auth = security::authenticated(token, &app.password);
        if !app.password.is_empty() && !password_auth && !capture_auth {
            return fail(StatusCode::UNAUTHORIZED, "请输入控制台访问口令").into_response();
        }
        if CAPTURE_PATHS.contains(&path.as_str()) && !capture_auth && !password_auth {
            return fail(StatusCode::UNAUTHORIZED, "请使用控制台生成的一次抓包口令")
                .into_response();
        }
        if request.method() == "POST"
            && headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .split(';')
                .next()
                != Some("application/json")
        {
            return fail(StatusCode::UNSUPPORTED_MEDIA_TYPE, "需要 application/json")
                .into_response();
        }
    }
    let mut response = next.run(request).await;
    for (key,val) in [
        ("referrer-policy","no-referrer"),("x-content-type-options","nosniff"),
        ("content-security-policy","default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")]{
        response.headers_mut().insert(axum::http::HeaderName::from_static(key),axum::http::HeaderValue::from_static(val));
    }
    if path.starts_with("/api/") && !path.ends_with("/stream") {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    }
    response
}
async fn config(State(app): State<Shared>) -> Json<Value> {
    let mut value = schemas::defaults();
    value["allow_private"] = json!(app.private);
    value["local_network_compat"] = json!(app.local_only);
    value["engine"] = json!(concat!("Rust ", env!("CARGO_PKG_VERSION")));
    Json(value)
}
struct Target {
    base: String,
    key: Zeroizing<String>,
    proxy: Option<Zeroizing<String>>,
    compatibility: bool,
}
fn target(value: &mut Value) -> Result<Target, Failure> {
    let obj = value
        .as_object_mut()
        .ok_or_else(|| fail(StatusCode::UNPROCESSABLE_ENTITY, "需要输入对象"))?;
    let base = obj
        .get("base_url")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 2048)
        .ok_or_else(|| fail(StatusCode::UNPROCESSABLE_ENTITY, "Base URL 无效"))?
        .to_owned();
    let key = obj
        .remove("api_key")
        .and_then(|v| v.as_str().map(str::to_owned))
        .filter(|s| !s.is_empty() && s.len() <= 4096)
        .ok_or_else(|| fail(StatusCode::UNPROCESSABLE_ENTITY, "API Key 为空或长度无效"))?;
    let key = Zeroizing::new(key);
    let proxy = obj
        .remove("proxy")
        .filter(|v| !v.is_null())
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or_else(|| fail(StatusCode::UNPROCESSABLE_ENTITY, "代理 URL 格式无效"))
        })
        .transpose()?;
    let proxy = proxy.map(Zeroizing::new);
    let compatibility = obj
        .remove("local_network_compat")
        .map(|v| {
            v.as_bool()
                .ok_or_else(|| fail(StatusCode::UNPROCESSABLE_ENTITY, "本机网络兼容选项无效"))
        })
        .transpose()?
        .unwrap_or(false);
    Ok(Target {
        base,
        key,
        proxy,
        compatibility,
    })
}
async fn open_relay(
    app: &App,
    peer: SocketAddr,
    target: Target,
    timeout: f64,
) -> Result<Relay, Failure> {
    Relay::open(
        &target.base,
        target.key,
        target.proxy,
        security::NetworkPolicy {
            private_targets: app.private,
            local: app.local_only && peer.ip().is_loopback(),
            compatibility: target.compatibility,
        },
        timeout,
    )
    .await
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"detail": e.message, "code": e.code})),
        )
    })
}
async fn models(
    State(app): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    bytes: Bytes,
) -> Result<Json<Value>, Failure> {
    let mut value = parse(&bytes)?;
    let target = target(&mut value)?;
    if value.as_object().unwrap().keys().any(|k| k != "base_url") {
        return Err(fail(StatusCode::UNPROCESSABLE_ENTITY, "模型请求字段无效"));
    }
    let relay = open_relay(&app, peer, target, 15.).await?;
    let mut row = crate::schemas::Row::new(1, 0, "模型列表", "models", json!({}));
    row.method = "GET".into();
    row.path = "/v1/models".into();
    row.disguised = false;
    let (r, data) = relay
        .exchange(
            row,
            json!({}),
            60.,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
    relay.forget();
    if let Some(error) = r.error {
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(json!({"detail":error,"snippet":r.snippet,"status":r.status})),
        ));
    }
    let models = data["data"]
        .as_array()
        .ok_or_else(|| fail(StatusCode::BAD_GATEWAY, "模型列表缺少 data 数组"))?;
    Ok(Json(
        json!({"models":models.iter().filter_map(|v|v["id"].as_str()).collect::<Vec<_>>()}),
    ))
}
async fn all_profiles(State(app): State<Shared>) -> Json<Value> {
    Json(json!(app.store.all()))
}
async fn add_profile(
    State(app): State<Shared>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Json<Value>, Failure> {
    let value = parse(&bytes)?;
    let p: Profile = if let Some(raw) = value.get("raw") {
        profiles::parse_import(
            raw.clone(),
            value["name"].as_str().unwrap_or("导入 Profile"),
            None,
        )
        .map_err(|_| {
            fail(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Profile JSON 或 cURL 格式无效",
            )
        })?
    } else {
        serde_json::from_value(value)
            .map_err(|_| fail(StatusCode::UNPROCESSABLE_ENTITY, "Profile JSON 格式无效"))?
    };
    let p = app
        .store
        .save(p, security::auth_values(&header_json(&headers)))
        .map_err(|e| fail(StatusCode::UNPROCESSABLE_ENTITY, e))?;
    Ok(Json(json!(p)))
}
async fn delete_profile(
    State(app): State<Shared>,
    Path(id): Path<String>,
) -> Result<Json<Value>, Failure> {
    if !app
        .store
        .delete(&id)
        .map_err(|e| fail(StatusCode::INTERNAL_SERVER_ERROR, e))?
    {
        return Err(fail(StatusCode::NOT_FOUND, "找不到可删除的自定义 Profile"));
    }
    Ok(Json(json!({"ok":true})))
}
fn header_json(headers: &HeaderMap) -> Value {
    Value::Object(
        headers
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str().into(), json!(v))))
            .collect(),
    )
}
async fn arm(State(app): State<Shared>) -> Json<Value> {
    let token = probes::nonce() + &probes::nonce();
    *app.capture.lock().unwrap() = Some(Capture {
        token: Zeroizing::new(token.clone()),
        until: Instant::now() + Duration::from_secs(300),
    });
    Json(json!({"token":token,"expires_in":300}))
}
async fn capture(
    State(app): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Result<Response, Failure> {
    if !peer.ip().is_loopback() {
        return Err(fail(StatusCode::FORBIDDEN, "抓包端点仅接受回环连接"));
    }
    {
        let mut guard = app.capture.lock().unwrap();
        let Some(window) = guard.as_ref().filter(|c| Instant::now() < c.until) else {
            return Err(fail(StatusCode::CONFLICT, "请先在控制台开启一次抓包"));
        };
        let token = bearer(request.headers());
        if !security::authenticated(token, &window.token)
            && !security::authenticated(token, &app.password)
        {
            return Err(fail(StatusCode::UNAUTHORIZED, "一次抓包口令无效"));
        }
        guard.take();
    }
    let protocol = if request.uri().path().ends_with("responses") {
        "responses"
    } else {
        "chat"
    };
    let headers = header_json(request.headers());
    let bytes = axum::body::to_bytes(request.into_body(), 16_000_000)
        .await
        .map_err(|_| fail(StatusCode::PAYLOAD_TOO_LARGE, "抓包请求过大"))?;
    let body = parse(&bytes)?;
    let mut profile = profiles::parse_import(
        json!({"headers":headers,"body":body}),
        "本机 Codex 抓包",
        Some(protocol),
    )
    .map_err(|_| {
        fail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "未识别捕获请求的 JSON 骨架",
        )
    })?;
    profile.source = "实机抓包复刻".into();
    let profile = app
        .store
        .save(profile, security::auth_values(&headers))
        .map_err(|e| fail(StatusCode::UNPROCESSABLE_ENTITY, e))?;
    let message = "已保存脱敏 Profile，可以返回控制台。";
    if body["stream"] != true {
        return Ok(Json(json!({"message":message,"profile_id":profile.id,"baseline_tokens":profile.baseline_tokens})).into_response());
    }
    let id = format!("capture_{}", probes::nonce());
    let mut output = String::new();
    if protocol == "responses" {
        let item = json!({"type":"message","id":format!("msg_{id}"),"role":"assistant","status":"completed","content":[{"type":"output_text","text":message,"annotations":[]}]});
        let response = json!({"id":id,"object":"response","model":"local-capture","status":"completed","output":[item]});
        for (typ, fields) in [
            (
                "response.created",
                json!({"response":{"id":id,"object":"response","model":"local-capture","status":"in_progress","output":[]}}),
            ),
            (
                "response.output_item.added",
                json!({"output_index":0,"item":{"type":"message","id":item["id"],"role":"assistant","status":"in_progress","content":[]}}),
            ),
            (
                "response.output_text.delta",
                json!({"output_index":0,"content_index":0,"item_id":item["id"],"delta":message}),
            ),
            (
                "response.output_item.done",
                json!({"output_index":0,"item":item}),
            ),
            ("response.completed", json!({"response":response})),
        ] {
            let mut v = fields;
            v["type"] = json!(typ);
            output.push_str(&format!("event: {typ}\ndata: {v}\n\n"));
        }
    } else {
        for (delta, finish) in [
            (json!({"role":"assistant","content":message}), Value::Null),
            (json!({}), json!("stop")),
        ] {
            let obj = json!({"id":id,"object":"chat.completion.chunk","model":"local-capture","choices":[{"index":0,"delta":delta,"finish_reason":finish}]});
            output.push_str(&format!("data: {obj}\n\n"));
        }
        output.push_str("data: [DONE]\n\n");
    }
    Ok((
        [
            (header::CONTENT_TYPE, "text/event-stream"),
            (
                axum::http::HeaderName::from_static("x-captured-profile-id"),
                profile.id.as_str(),
            ),
        ],
        output,
    )
        .into_response())
}
async fn create_run(
    State(app): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    bytes: Bytes,
) -> Result<Json<Value>, Failure> {
    let mut value = parse(&bytes)?;
    let target = target(&mut value)?;
    let mut spec: Spec = serde_json::from_value(value)
        .map_err(|_| fail(StatusCode::UNPROCESSABLE_ENTITY, "输入字段格式无效"))?;
    spec.validate()
        .map_err(|e| fail(StatusCode::UNPROCESSABLE_ENTITY, e))?;
    if probes::selected(&spec).is_empty() {
        return Err(fail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "高开销探针需显式开启对应开关",
        ));
    }
    let profile = app
        .store
        .get(&spec.profile_id)
        .ok_or_else(|| fail(StatusCode::UNPROCESSABLE_ENTITY, "所选 Profile 不存在"))?;
    let relay = open_relay(&app, peer, target, spec.controls.connect_s).await?;
    spec.base_url = relay.base.clone();
    spec = serde_json::from_value(relay.sanitize(&json!(spec)))
        .map_err(|_| fail(StatusCode::UNPROCESSABLE_ENTITY, "输入字段格式无效"))?;
    let run = Run::new(spec, profile, relay);
    let created =
        json!({"run_id":run.id,"estimate":probes::estimate(&run.spec,&run.ids),"selected":run.ids});
    app.runs.lock().unwrap().insert(run.id.clone(), run.clone());
    tokio::spawn(run.execute());
    Ok(Json(created))
}
fn lookup(app: &App, id: &str) -> Result<Arc<Run>, Failure> {
    app.runs
        .lock()
        .unwrap()
        .get(id)
        .cloned()
        .ok_or_else(|| fail(StatusCode::NOT_FOUND, "运行不存在或已过保留时间"))
}
async fn stream(
    State(app): State<Shared>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, Failure> {
    let run = lookup(&app, &id)?;
    let mut cursor = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("0")
        .parse::<usize>()
        .map_err(|_| fail(StatusCode::BAD_REQUEST, "事件序号无效"))?;
    if cursor > run.data.lock().unwrap().events.len() {
        return Err(fail(StatusCode::BAD_REQUEST, "事件序号超出范围"));
    }
    let events = async_stream::stream! {
        loop{
            let notify=run.changed.notified();
            let (batch,finished)={
                let d=run.data.lock().unwrap();
                (d.events[cursor..].to_vec(),d.finished.is_some())
            };
            for (kind,value) in batch{
                cursor+=1;
                yield Ok::<Event,Infallible>(Event::default().id(cursor.to_string()).event(kind).data(value.to_string()));
            }
            if finished{break}
            let _=tokio::time::timeout(Duration::from_secs(12),notify).await;
        }
    };
    let mut response = Sse::new(events)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(12)))
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-cache".parse().unwrap());
    response
        .headers_mut()
        .insert(header::CONNECTION, "keep-alive".parse().unwrap());
    response
        .headers_mut()
        .insert("x-accel-buffering", "no".parse().unwrap());
    Ok(response)
}
async fn abort(State(app): State<Shared>, Path(id): Path<String>) -> Result<Json<Value>, Failure> {
    lookup(&app, &id)?.abort().await;
    Ok(Json(json!({"ok":true})))
}
async fn static_file(request: Request) -> Response {
    let (content, kind): (&[u8], &str) = match request.uri().path() {
        "/" | "/index.html" => (
            include_bytes!("../static/index.html"),
            "text/html; charset=utf-8",
        ),
        "/styles.css" => (
            include_bytes!("../static/styles.css"),
            "text/css; charset=utf-8",
        ),
        "/js/api.js" => (
            include_bytes!("../static/js/api.js"),
            "text/javascript; charset=utf-8",
        ),
        "/js/state.js" => (
            include_bytes!("../static/js/state.js"),
            "text/javascript; charset=utf-8",
        ),
        "/js/main.js" => (
            include_bytes!("../static/js/main.js"),
            "text/javascript; charset=utf-8",
        ),
        "/js/report.js" => (
            include_bytes!("../static/js/report.js"),
            "text/javascript; charset=utf-8",
        ),
        "/js/export.js" => (
            include_bytes!("../static/js/export.js"),
            "text/javascript; charset=utf-8",
        ),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    (
        [
            (header::CONTENT_TYPE, kind),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        Body::from(content),
    )
        .into_response()
}
pub async fn serve() -> Result<(), String> {
    let host = std::env::var("HOST").unwrap_or("127.0.0.1".into());
    let explicit = std::env::var("PORT").ok();
    let port = explicit
        .as_deref()
        .unwrap_or("8787")
        .parse::<u16>()
        .map_err(|_| "PORT 无效")?;
    let mut listener = tokio::net::TcpListener::bind((host.as_str(), port)).await;
    if explicit.is_none() && listener.is_err() {
        for fallback in 8788..=8799 {
            listener = tokio::net::TcpListener::bind((host.as_str(), fallback)).await;
            if listener.is_ok() {
                break;
            }
        }
    }
    let listener = listener.map_err(|e| format!("监听失败 ({e})"))?;
    let addr = listener.local_addr().map_err(|_| "无法读取监听地址")?;
    let data = std::env::var_os("PROBE_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("LOCALAPPDATA")
                .map(PathBuf::from)
                .map(|p| p.join("RelayProbe"))
                .unwrap_or(PathBuf::from(".runtime"))
        });
    let app = Arc::new(App {
        password: Zeroizing::new(std::env::var("ACCESS_PASSWORD").unwrap_or_default()),
        private: std::env::var("ALLOW_PRIVATE_TARGETS")
            .is_ok_and(|s| s.eq_ignore_ascii_case("true")),
        store: Store::new(data.join("profiles.json"))?,
        runs: Mutex::new(HashMap::new()),
        capture: Mutex::new(None),
        local_only: addr.ip().is_loopback(),
    });
    let routes = Router::new()
        .route("/api/config", get(config))
        .route("/api/models", post(models))
        .route("/api/profiles", get(all_profiles).post(add_profile))
        .route("/api/profiles/{id}", delete(delete_profile))
        .route("/api/capture/arm", post(arm))
        .route(CAPTURE_PATHS[0], post(capture))
        .route(CAPTURE_PATHS[1], post(capture))
        .route("/api/runs", post(create_run))
        .route("/api/runs/{id}/stream", get(stream))
        .route("/api/runs/{id}/abort", post(abort))
        .fallback(static_file)
        .layer(DefaultBodyLimit::max(16_000_000))
        .layer(middleware::from_fn_with_state(app.clone(), protect))
        .with_state(app.clone());
    let expiry = app.clone();
    let cleanup = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            expiry.runs.lock().unwrap().retain(|_, run| {
                run.data
                    .lock()
                    .unwrap()
                    .finished
                    .is_none_or(|t| t.elapsed() < Duration::from_secs(1800))
            });
        }
    });
    let open_host = if addr.ip().is_unspecified() {
        "127.0.0.1".into()
    } else {
        addr.ip().to_string()
    };
    let open_host = if open_host.contains(':') {
        format!("[{open_host}]")
    } else {
        open_host
    };
    let url = format!("http://{open_host}:{}", addr.port());
    println!(
        "中转站渠道质量探针 {} · Rust\n{url}\n关闭此窗口或按 Ctrl+C 退出。",
        env!("CARGO_PKG_VERSION")
    );
    if !std::env::args().any(|s| s == "--no-open") {
        open_browser(&url);
    }
    let shutdown = app.clone();
    let result = axum::serve(
        listener,
        routes.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        let _ = tokio::signal::ctrl_c().await;
        let runs: Vec<_> = shutdown.runs.lock().unwrap().values().cloned().collect();
        for run in &runs {
            run.cancel.cancel();
        }
        for run in runs {
            run.abort().await;
        }
    })
    .await;
    cleanup.abort();
    result.map_err(|e| format!("服务已退出 ({e})"))
}
fn open_browser(url: &str) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = std::process::Command::new("rundll32.exe")
            .args(["url.dll,FileProtocolHandler", url])
            .creation_flags(0x08000000)
            .spawn();
    }
    #[cfg(not(windows))]
    {
        let _ = std::process::Command::new(if cfg!(target_os = "macos") {
            "open"
        } else {
            "xdg-open"
        })
        .arg(url)
        .spawn();
    }
}
