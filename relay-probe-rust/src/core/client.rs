use super::{
    protocols,
    security::{self, Address, NetworkPolicy, TargetError},
    tokenizer,
};
use crate::schemas::Row;
use axum::body::Bytes;
use base64::Engine;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Uri};
use hyper_util::{
    client::legacy::{
        connect::{Connected, Connection},
        Client,
    },
    rt::{TokioExecutor, TokioIo},
};
use serde_json::{json, Value};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_util::sync::CancellationToken;
use tower_service::Service;
use zeroize::{Zeroize, Zeroizing};

trait Socket: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Socket for T {}
type Wire = Box<dyn Socket>;
#[derive(Clone, Debug)]
struct Phases(Value);
pub struct ConnectionIo {
    io: TokioIo<Wire>,
    phases: Phases,
}
impl Connection for ConnectionIo {
    fn connected(&self) -> Connected {
        Connected::new().extra(self.phases.clone())
    }
}
impl hyper::rt::Read for ConnectionIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl hyper::rt::Write for ConnectionIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
#[derive(Clone)]
pub struct Connector {
    dest: Address,
    proxy: Option<Address>,
    timeout: Duration,
    tls: tokio_native_tls::TlsConnector,
}
fn err(message: impl ToString) -> io::Error {
    io::Error::other(message.to_string())
}
async fn tls(io: Wire, name: &str, connector: &tokio_native_tls::TlsConnector) -> io::Result<Wire> {
    Ok(Box::new(
        connector
            .connect(name, io)
            .await
            .map_err(|e| err(format!("TLS 证书或握手错误 ({e})")))?,
    ))
}
impl Connector {
    async fn open(self) -> io::Result<ConnectionIo> {
        let start = Instant::now();
        let addr = self.proxy.as_ref().unwrap_or(&self.dest);
        let tcp = TcpStream::connect(addr.socket)
            .await
            .map_err(|e| err(format!("连接失败 ({e})")))?;
        tcp.set_nodelay(true)?;
        let mut phases = json!({"connect_tcp":start.elapsed().as_secs_f64()});
        let mut io: Wire = Box::new(tcp);
        if let Some(proxy) = &self.proxy {
            let begin = Instant::now();
            if proxy.url.scheme() == "https" {
                io = tls(io, &proxy.host, &self.tls).await?;
            }
            if proxy.url.scheme() == "socks5" {
                let auth = !proxy.url.username().is_empty();
                io.write_all(if auth { &[5, 2, 0, 2] } else { &[5, 1, 0] })
                    .await?;
                let mut response = [0; 2];
                io.read_exact(&mut response).await?;
                if response[0] != 5 || ![0, 2].contains(&response[1]) {
                    return Err(err("SOCKS5 代理认证协商失败"));
                }
                if response[1] == 2 {
                    let user = url_decode(proxy.url.username());
                    let pass = Zeroizing::new(url_decode(proxy.url.password().unwrap_or("")));
                    if user.len() > 255 || pass.len() > 255 {
                        return Err(err("SOCKS5 凭据过长"));
                    }
                    let mut packet = Zeroizing::new(vec![1, user.len() as u8]);
                    packet.extend_from_slice(user.as_bytes());
                    packet.push(pass.len() as u8);
                    packet.extend_from_slice(pass.as_bytes());
                    io.write_all(&packet).await?;
                    io.read_exact(&mut response).await?;
                    if response != [1, 0] {
                        return Err(err("SOCKS5 代理认证失败"));
                    }
                }
                let mut request = vec![5, 1, 0];
                match self.dest.socket.ip() {
                    std::net::IpAddr::V4(ip) => {
                        request.push(1);
                        request.extend_from_slice(&ip.octets());
                    }
                    std::net::IpAddr::V6(ip) => {
                        request.push(4);
                        request.extend_from_slice(&ip.octets());
                    }
                }
                request.extend_from_slice(&self.dest.socket.port().to_be_bytes());
                io.write_all(&request).await?;
                let mut head = [0; 4];
                io.read_exact(&mut head).await?;
                if head[0] != 5 || head[1] != 0 {
                    return Err(err("SOCKS5 代理连接失败"));
                }
                let n = match head[3] {
                    1 => 4,
                    4 => 16,
                    3 => io.read_u8().await? as usize,
                    _ => return Err(err("SOCKS5 地址响应无效")),
                };
                let mut tail = vec![0; n + 2];
                io.read_exact(&mut tail).await?;
            } else {
                let authority = self.dest.socket.to_string();
                let mut request = Zeroizing::new(format!(
                    "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
                ));
                if !proxy.url.username().is_empty() {
                    let pair = Zeroizing::new(format!(
                        "{}:{}",
                        url_decode(proxy.url.username()),
                        url_decode(proxy.url.password().unwrap_or(""))
                    ));
                    let encoded = Zeroizing::new(
                        base64::engine::general_purpose::STANDARD.encode(pair.as_bytes()),
                    );
                    request.push_str(&format!(
                        "Proxy-Authorization: Basic {}\r\n",
                        encoded.as_str()
                    ));
                }
                request.push_str("\r\n");
                io.write_all(request.as_bytes()).await?;
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    if header.len() > 16384 {
                        return Err(err("HTTP 代理响应头过长"));
                    }
                    header.push(io.read_u8().await?);
                }
                let code = String::from_utf8_lossy(&header)
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("")
                    .to_string();
                if code != "200" {
                    return Err(err(format!("HTTP 代理 CONNECT 失败，状态 {code}")));
                }
            }
            phases["proxy_tunnel"] = json!(begin.elapsed().as_secs_f64());
        }
        if self.dest.url.scheme() == "https" {
            let at = Instant::now();
            io = tls(io, &self.dest.host, &self.tls).await?;
            phases["tls_handshake"] = json!(at.elapsed().as_secs_f64());
        }
        Ok(ConnectionIo {
            io: TokioIo::new(io),
            phases: Phases(phases),
        })
    }
}
fn url_decode(s: &str) -> String {
    let mut bytes = vec![];
    let mut i = 0;
    while i < s.len() {
        if s.as_bytes()[i] == b'%' && i + 2 < s.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                bytes.push(v);
                i += 3;
                continue;
            }
        }
        bytes.push(s.as_bytes()[i]);
        i += 1;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}
impl Service<Uri> for Connector {
    type Response = ConnectionIo;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<ConnectionIo>> + Send>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, _: Uri) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            tokio::time::timeout(this.timeout, this.open())
                .await
                .map_err(|_| err("连接超时"))?
        })
    }
}
pub struct Relay {
    pub base: String,
    http: Mutex<Option<Client<Connector, Full<Bytes>>>>,
    secrets: Mutex<Vec<Zeroizing<String>>>,
}
impl Relay {
    pub async fn open(
        base: &str,
        key: Zeroizing<String>,
        proxy: Option<Zeroizing<String>>,
        policy: NetworkPolicy,
        connect: f64,
    ) -> Result<Self, TargetError> {
        let dest = security::address(base, false, policy, connect).await?;
        let proxy_addr = match proxy.as_ref().filter(|s| !s.is_empty()) {
            Some(text) => Some(security::address(text, true, policy, connect).await?),
            None => None,
        };
        let mut builder = native_tls::TlsConnector::builder();
        // Explicit CA file is useful for enterprise roots and the local TLS acceptance fixture.
        if let Ok(path) = std::env::var("SSL_CERT_FILE") {
            let bytes = std::fs::read(path).map_err(|_| "TLS CA 文件无法读取")?;
            builder.add_root_certificate(
                native_tls::Certificate::from_pem(&bytes).map_err(|_| "TLS CA 文件无效")?,
            );
        }
        let connector = Connector {
            dest: dest.clone(),
            proxy: proxy_addr.clone(),
            timeout: Duration::from_secs_f64(connect),
            tls: builder.build().map_err(|_| "TLS 初始化失败")?.into(),
        };
        let mut secrets = vec![key];
        if let Some(p) = proxy {
            secrets.push(p);
        }
        if let Some(p) = &proxy_addr {
            if let Some(pass) = p.url.password() {
                secrets.push(Zeroizing::new(url_decode(pass)));
            }
        }
        let http = Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(50)
            .build(connector);
        Ok(Self {
            base: dest.url.as_str().trim_end_matches('/').to_owned(),
            http: Mutex::new(Some(http)),
            secrets: Mutex::new(secrets),
        })
    }
    pub fn sanitize(&self, value: &Value) -> Value {
        let secrets = self.secrets.lock().unwrap();
        security::scrub(
            value,
            &secrets.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
    }
    pub fn forget(&self) {
        self.secrets.lock().unwrap().clear();
        self.http.lock().unwrap().take();
    }
    pub async fn exchange(
        &self,
        mut row: Row,
        headers: Value,
        read: f64,
        cancel: CancellationToken,
    ) -> (Row, Value) {
        let start = Instant::now();
        let secrets: Vec<Zeroizing<String>> = self
            .secrets
            .lock()
            .unwrap()
            .iter()
            .map(|s| Zeroizing::new(s.to_string()))
            .collect();
        let http = self.http.lock().unwrap().clone();
        let key = secrets.first().map(|s| s.as_str()).unwrap_or("");
        let mut data = Value::Null;
        let outcome = tokio::select! {
            biased;
            _=cancel.cancelled()=>Err("已取消在途请求".to_owned()),
            value=self.transfer(&mut row,headers,key,http,read,start)=>value,
        };
        match outcome {
            Ok(v) => data = v,
            Err(e) => {
                row.error = Some(e);
            }
        }
        row.elapsed = start.elapsed().as_secs_f64();
        protocols::counts(&mut row);
        row.local_output = tokenizer::count(&row.text);
        row.input_delta = row.n("input").map(|v| v - row.local_input as i64);
        let mut plain: Vec<String> = secrets.iter().map(|s| s.to_string()).collect();
        let mut safe = security::scrub(&json!(row), &plain);
        // These are fixed internal metric names, never user-controlled secret fields.
        safe["counts"] = json!(row.counts);
        let safe_row: Row = serde_json::from_value(safe).expect("sanitized row schema");
        data = security::scrub(&data, &plain);
        for secret in &mut plain {
            secret.zeroize();
        }
        (safe_row, data)
    }
    async fn transfer(
        &self,
        row: &mut Row,
        headers: Value,
        key: &str,
        http: Option<Client<Connector, Full<Bytes>>>,
        read: f64,
        start: Instant,
    ) -> Result<Value, String> {
        let http = http.ok_or("已取消在途请求")?;
        let url = format!("{}{}", self.base, row.path);
        let mut request = Request::builder().method(row.method.as_str()).uri(url);
        let safe_headers = security::clean_headers(&headers, &[]);
        if let Some(obj) = safe_headers.as_object() {
            for (k, v) in obj {
                request = request.header(k, v.as_str().unwrap_or(""));
            }
        }
        request = request.header("authorization", format!("Bearer {key}"));
        let payload = if row.method == "POST" {
            request = request.header("content-type", "application/json");
            Bytes::from(serde_json::to_vec(&row.body).unwrap())
        } else {
            Bytes::new()
        };
        let request = request
            .body(Full::new(payload))
            .map_err(|_| "请求头格式无效")?;
        row.headers = Value::Object(
            request
                .headers()
                .iter()
                .filter_map(|(k, v)| v.to_str().ok().map(|s| (k.as_str().into(), json!(s))))
                .collect(),
        );
        let limit = Duration::from_secs_f64(read);
        let response = tokio::time::timeout(limit, http.request(request))
            .await
            .map_err(|_| "读超时")?
            .map_err(|e| {
                let mut text = e.to_string();
                let mut source = std::error::Error::source(&e);
                while let Some(s) = source {
                    text.push_str(&format!(" ({s})"));
                    source = s.source();
                }
                text
            })?;
        row.status = Some(response.status().as_u16());
        row.response_headers = Value::Object(
            response
                .headers()
                .iter()
                .filter_map(|(k, v)| v.to_str().ok().map(|s| (k.as_str().into(), json!(s))))
                .collect(),
        );
        if let Some(Phases(p)) = response.extensions().get::<Phases>() {
            row.phases = p.clone();
        }
        row.phases["request_to_headers"] = json!(start.elapsed().as_secs_f64());
        let sse = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("text/event-stream"));
        let bad = !response.status().is_success();
        let mut body = response.into_body();
        let mut buffer = Vec::new();
        let mut event = String::new();
        let mut pieces = Vec::new();
        let mut received = 0;
        while let Some(frame) = tokio::time::timeout(limit, body.frame())
            .await
            .map_err(|_| "读超时")?
        {
            let frame = frame.map_err(|e| format!("上游协议中断 ({e})"))?;
            let Ok(bytes) = frame.into_data() else {
                continue;
            };
            received += bytes.len();
            if received > 12_000_000 {
                return Err("响应超出采样上限".into());
            }
            if bad {
                buffer.extend_from_slice(&bytes[..bytes.len().min(4096 - buffer.len())]);
                if buffer.len() == 4096 {
                    break;
                }
                continue;
            }
            buffer.extend_from_slice(&bytes);
            if row.stream && sse {
                while let Some(end) = buffer.iter().position(|b| *b == b'\n') {
                    let line = String::from_utf8_lossy(&buffer[..end])
                        .trim_end_matches('\r')
                        .to_owned();
                    buffer.drain(..=end);
                    if line.is_empty() {
                        flush(row, &mut pieces, &event, start)?;
                        event.clear();
                    } else if let Some(s) = line.strip_prefix("event:") {
                        event = s.trim().into();
                    } else if let Some(s) = line.strip_prefix("data:") {
                        pieces.push(s.trim_start_matches(' ').to_owned());
                    }
                }
            }
        }
        row.phases["total_transfer"] = json!(start.elapsed().as_secs_f64());
        if bad {
            row.snippet = String::from_utf8_lossy(&buffer).into_owned();
            return Err(format!("HTTP {}", row.status.unwrap()));
        }
        if row.stream && sse {
            if !buffer.is_empty() {
                let last = String::from_utf8_lossy(&buffer);
                if let Some(s) = last.strip_prefix("data:") {
                    pieces.push(s.trim().into());
                }
            }
            flush(row, &mut pieces, &event, start)?;
            if !row.complete && row.error.is_none() {
                row.error = Some("流未收到正常终止事件".into());
            }
            Ok(Value::Null)
        } else {
            let value: Value = serde_json::from_slice(&buffer).map_err(|_| "响应 JSON 解析失败")?;
            if value.get("error").is_some() {
                row.snippet = value["error"].to_string();
                return Err("上游返回错误对象".into());
            }
            if row.method == "GET" {
                row.complete = value.is_object();
            } else {
                if row.stream {
                    row.error = Some("请求 SSE，实际返回非流式响应".into());
                }
                protocols::absorb(row, &value, "", start.elapsed().as_secs_f64());
            }
            Ok(value)
        }
    }
}
fn flush(
    row: &mut Row,
    pieces: &mut Vec<String>,
    event: &str,
    start: Instant,
) -> Result<(), String> {
    if pieces.is_empty() {
        return Ok(());
    }
    let raw = pieces.join("\n");
    pieces.clear();
    if raw == "[DONE]" {
        row.events.push("[DONE]".into());
        if row.protocol == "chat" {
            row.complete = row.finish.is_some();
        }
        return Ok(());
    }
    let obj: Value = serde_json::from_str(&raw).map_err(|_| "SSE JSON 解析失败")?;
    row.events.push(
        if event.is_empty() {
            obj["type"].as_str().unwrap_or("message")
        } else {
            event
        }
        .into(),
    );
    protocols::absorb(row, &obj, event, start.elapsed().as_secs_f64());
    Ok(())
}
