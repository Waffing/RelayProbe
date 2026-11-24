use regex::Regex;
use serde_json::Value;
use std::{
    net::{IpAddr, SocketAddr},
    sync::LazyLock,
    time::Duration,
};
use subtle::ConstantTimeEq;
use url::{Host, Url};

static AUTH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)authorization|api[-_]?key|cookie|password|credential|secret|access[-_]?token|refresh[-_]?token|bearer|auth[-_]?token|signature").unwrap()
});
static KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:sk|rk|sess)-[a-z0-9_-]{6,}").unwrap());
static BEARER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+").unwrap());
static QUERY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)([?&](?:key|api[_-]?key|token|auth|signature)=)[^&\s"']+"#).unwrap()
});
pub fn authenticated(value: &str, password: &str) -> bool {
    !password.is_empty() && bool::from(value.as_bytes().ct_eq(password.as_bytes()))
}
pub fn scrub(value: &Value, secrets: &[String]) -> Value {
    match value {
        Value::Object(obj) => Value::Object(
            obj.iter()
                .filter(|(k, _)| !AUTH.is_match(k))
                .map(|(k, v)| (scrub_text(k, secrets), scrub(v, secrets)))
                .collect(),
        ),
        Value::Array(arr) => Value::Array(arr.iter().map(|v| scrub(v, secrets)).collect()),
        Value::String(s) => Value::String(scrub_text(s, secrets)),
        _ => value.clone(),
    }
}
pub fn scrub_text(text: &str, secrets: &[String]) -> String {
    let mut text = text.to_owned();
    for secret in secrets {
        if !secret.is_empty() {
            text = text.replace(secret, "[已脱敏]");
        }
    }
    QUERY
        .replace_all(
            &BEARER.replace_all(&KEY.replace_all(&text, "[已脱敏]"), "[已脱敏]"),
            "$1[已脱敏]",
        )
        .into_owned()
}
pub fn auth_values(value: &Value) -> Vec<String> {
    let mut out = vec![];
    match value {
        Value::Object(obj) => {
            for (k, v) in obj {
                if AUTH.is_match(k) {
                    if let Some(s) = v.as_str() {
                        out.push(s.into());
                        out.push(s.rsplit_once(' ').map(|x| x.1).unwrap_or(s).into());
                    }
                }
                out.extend(auth_values(v));
            }
        }
        Value::Array(a) => {
            for v in a {
                out.extend(auth_values(v));
            }
        }
        _ => {}
    }
    out
}
pub fn clean_headers(value: &Value, secrets: &[String]) -> Value {
    let mut out = serde_json::Map::new();
    if let Some(obj) = value.as_object() {
        for (k, v) in obj {
            let name = k.to_ascii_lowercase();
            let Some(s) = v.as_str() else { continue };
            if AUTH.is_match(k)
                || [
                    "host",
                    "origin",
                    "referer",
                    "connection",
                    "content-length",
                    "transfer-encoding",
                    "accept-encoding",
                    "forwarded",
                    "via",
                    "x-real-ip",
                    "proxy-connection",
                    "upgrade",
                    "te",
                    "trailer",
                ]
                .contains(&name.as_str())
                || ["sec-", "proxy-", "x-forwarded-"]
                    .iter()
                    .any(|p| name.starts_with(p))
                || !name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
                || !s.is_ascii()
                || s.contains(['\r', '\n'])
            {
                continue;
            }
            out.insert(name, Value::String(scrub_text(s, secrets)));
        }
    }
    Value::Object(out)
}
pub fn allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let [x, y, z, _] = a.octets();
            !a.is_private()
                && !a.is_loopback()
                && !a.is_link_local()
                && !a.is_unspecified()
                && !a.is_multicast()
                && !a.is_broadcast()
                && !a.is_documentation()
                && x != 0
                && x < 240
                && !(x == 100 && (64..=127).contains(&y))
                && !(x == 198 && (y == 18 || y == 19))
                && !(x == 192 && y == 0 && z == 0)
                && !(x == 192 && y == 88 && z == 99)
        }
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return allowed(v4.into());
            }
            let s = a.segments();
            // Admit global unicast, excluding transition, documentation and reserved blocks.
            (s[0] & 0xe000) == 0x2000
                && s[0] != 0x2002
                && !(s[0] == 0x2001 && (s[1] < 0x200 || s[1] == 0xdb8))
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}
#[derive(Clone)]
pub struct Address {
    pub url: Url,
    pub socket: SocketAddr,
    pub host: String,
}

#[derive(Clone, Copy)]
pub struct NetworkPolicy {
    pub private_targets: bool,
    pub local: bool,
    pub compatibility: bool,
}

#[derive(Debug)]
pub struct TargetError {
    pub message: &'static str,
    pub code: Option<&'static str>,
}

impl From<&'static str> for TargetError {
    fn from(message: &'static str) -> Self {
        Self {
            message,
            code: None,
        }
    }
}

fn fake_ip(ip: IpAddr) -> bool {
    let ipv4 = match ip {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(ip) => ip,
            None => return false,
        },
    };
    matches!(ipv4.octets(), [198, 18 | 19, ..])
}

fn check_addresses(
    url: &Url,
    ips: &[SocketAddr],
    proxy: bool,
    policy: NetworkPolicy,
) -> Result<(), TargetError> {
    if ips.is_empty() {
        return Err("DNS 未返回可连接地址".into());
    }
    if policy.private_targets || ips.iter().all(|addr| allowed(addr.ip())) {
        return Ok(());
    }
    if policy.local {
        let compatible = if proxy {
            let loopback_host = match url.host() {
                Some(Host::Ipv4(ip)) => ip.is_loopback(),
                Some(Host::Ipv6(ip)) => ip.is_loopback(),
                Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
                None => false,
            };
            loopback_host && ips.iter().all(|addr| addr.ip().is_loopback())
        } else {
            let named_host = matches!(url.host(), Some(Host::Domain(host)) if host.trim_end_matches('.').contains('.'));
            url.scheme() == "https"
                && named_host
                && ips
                    .iter()
                    .all(|addr| allowed(addr.ip()) || fake_ip(addr.ip()))
        };
        if compatible {
            return if policy.compatibility {
                Ok(())
            } else {
                Err(TargetError {
                    code: Some("local_network_compat"),
                    message: if proxy {
                        "SSRF 已拦截本机代理。启用本机代理与 Fake-IP 兼容后重试。"
                    } else {
                        "SSRF 检测到目标域名使用 Fake-IP。启用本机代理与 Fake-IP 兼容后重试。"
                    },
                })
            };
        }
    }
    Err(if proxy {
        "SSRF 已拦截非公网代理。请使用公网代理或受信本机代理。"
    } else {
        "SSRF 已拦截非公网目标。请检查 Base URL 和 DNS 解析。"
    }
    .into())
}

pub async fn address(
    raw: &str,
    proxy: bool,
    policy: NetworkPolicy,
    seconds: f64,
) -> Result<Address, TargetError> {
    let mut url = Url::parse(raw.trim()).map_err(|_| "URL 无效，请检查协议、域名与端口")?;
    let schemes = if proxy {
        vec!["http", "https", "socks5"]
    } else {
        vec!["http", "https"]
    };
    if !schemes.contains(&url.scheme())
        || url.host_str().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
        || (!proxy && (!url.username().is_empty() || url.password().is_some()))
        || (proxy && !["", "/"].contains(&url.path()))
        || raw.contains('\\')
        || raw.chars().any(|c| c.is_control())
        || raw
            .split("://")
            .nth(1)
            .unwrap_or("")
            .split('/')
            .next()
            .unwrap_or("")
            .contains('%')
            && !proxy
    {
        return Err("URL 无效，请移除鉴权信息、查询参数和片段".into());
    }
    let path = url.path().trim_end_matches('/').to_owned();
    if !proxy {
        url.set_path(path.strip_suffix("/v1").unwrap_or(&path));
    }
    let host = url.host_str().unwrap().trim_matches(['[', ']']).to_owned();
    let port = url.port_or_known_default().unwrap_or(1080);
    let ips = tokio::time::timeout(
        Duration::from_secs_f64(seconds),
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await
    .map_err(|_| "DNS 解析超时")?
    .map_err(|_| "DNS 解析失败")?
    .collect::<Vec<_>>();
    check_addresses(&url, &ips, proxy, policy)?;
    // Prefer IPv4 when both are present, while checking every DNS answer above.
    let socket = *ips.iter().find(|a| a.is_ipv4()).unwrap_or(&ips[0]);
    Ok(Address { url, socket, host })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_compatibility_only_admits_scoped_addresses() {
        let check = |url: &str, ips: &[&str], proxy, local, compatibility| {
            let sockets: Vec<_> = ips.iter().map(|ip| ip.parse().unwrap()).collect();
            check_addresses(
                &Url::parse(url).unwrap(),
                &sockets,
                proxy,
                NetworkPolicy {
                    private_targets: false,
                    local,
                    compatibility,
                },
            )
        };
        let https = "https://relay.example.com";
        let fake = "198.18.1.42:443";
        let loopback = "127.0.0.1:443";
        let blocked = check(https, &[fake], false, true, false).unwrap_err();
        assert_eq!(blocked.code, Some("local_network_compat"));
        assert!(check(https, &[fake, "8.8.8.8:443"], false, true, true).is_ok());
        for (url, ips) in [
            ("http://relay.example.com", vec![fake]),
            ("https://198.18.1.42", vec![fake]),
            (https, vec![fake, loopback]),
            (https, vec![fake, "169.254.169.254:443"]),
            (https, vec!["10.0.0.1:443"]),
            ("https://127.0.0.1", vec![loopback]),
        ] {
            assert!(check(url, &ips, false, true, true).is_err());
        }
        assert!(check(https, &[fake], false, false, true).is_err());
        assert!(check(
            "http://localhost",
            &[loopback, "[::1]:443"],
            true,
            true,
            true
        )
        .is_ok());
        assert!(check(
            "http://localhost",
            &[loopback, "10.0.0.1:443"],
            true,
            true,
            true
        )
        .is_err());
        assert!(check("http://proxy.example.com", &[loopback], true, true, true).is_err());
        assert!(check("http://127.0.0.1", &[loopback], true, false, true).is_err());
    }
}
