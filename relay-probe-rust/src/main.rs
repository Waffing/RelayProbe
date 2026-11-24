mod core;
mod probes;
mod schemas;
mod server;

#[tokio::main]
async fn main() {
    let version = env!("CARGO_PKG_VERSION");
    if std::env::args().any(|a| a == "--version") {
        println!("Relay Probe {version} · Rust");
        return;
    }
    if std::env::args().any(|a| a == "--help") {
        println!("Relay Probe {version}\n双击打开本机控制台。关闭窗口或按 Ctrl+C 退出。\n--no-open  启动服务时不打开浏览器\n环境变量 HOST PORT ACCESS_PASSWORD ALLOW_PRIVATE_TARGETS PROBE_DATA_DIR SSL_CERT_FILE");
        return;
    }
    core::tokenizer::init();
    if let Err(message) = server::serve().await {
        eprintln!("{message}");
        std::process::exit(1);
    }
}
