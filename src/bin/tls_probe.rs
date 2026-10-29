//! TLS 指纹自检：用**本项目真实传输层**（`flow::http`，wreq + BoringSSL）打
//! `https://tls.browserleaks.com/json`，打印 `ja3_hash` / `ja4`，确认服务端看到的
//! 是 Chrome 档而不是 reqwest 时代的 OpenSSL/rustls 指纹。
//!
//! 用法：
//! ```text
//! cargo run --release --bin tls_probe
//! cargo run --release --bin tls_probe -- --proxy socks5h://127.0.0.1:1080
//! TURB_WREQ_EMULATION=Chrome146 cargo run --release --bin tls_probe
//! ```

use anyhow::{bail, Result};
use sentinel_rs::flow::http::{self, Client, RequestSpec};
use serde_json::Value;

const DEFAULT_URL: &str = "https://tls.browserleaks.com/json";

#[tokio::main]
async fn main() -> Result<()> {
    let mut url = DEFAULT_URL.to_string();
    let mut proxy: Option<String> = std::env::var("TURB_WREQ_PROXY").ok();

    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut iter = argv.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--url" => url = iter.next().cloned().unwrap_or_default(),
            "--proxy" => proxy = iter.next().cloned(),
            "-h" | "--help" => {
                println!(
                    "用法: tls_probe [--url URL] [--proxy PROXY]\n\
                     环境变量: TURB_WREQ_EMULATION（默认 Chrome149）/ TURB_WREQ_PROXY"
                );
                return Ok(());
            }
            other => bail!("未识别的参数: {other:?}（可用 --url / --proxy）"),
        }
    }
    if url.is_empty() {
        bail!("--url 不能为空");
    }

    // UA 传空串 → 用 emulation profile 自带的那条 Chrome UA。
    let client = Client::build("", proxy.as_deref(), http::RetryPolicy::default())?;
    println!("emulation : {:?}", client.emulation);
    println!("proxy     : {}", proxy.as_deref().unwrap_or("<直连>"));
    println!("url       : {url}");

    let resp = client.execute(&RequestSpec::get("tls.probe", url)).await?;
    println!("status    : {}", resp.status);
    println!("body      : {}", resp.body);

    let Ok(json) = serde_json::from_str::<Value>(&resp.body) else {
        println!("（响应不是 JSON，跳过字段提取）");
        return Ok(());
    };
    println!("\n-- 指纹 --");
    for key in [
        "ja3_hash",
        "ja3",
        "ja4",
        "ja4_r",
        "ja4_h2",
        "akamai",
        "user_agent",
        "tls_version",
        "http_version",
    ] {
        if let Some(value) = json.get(key) {
            println!("  {key:12}= {}", one_line(value));
        }
    }
    Ok(())
}

fn one_line(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}
