//! 与 `sentinel-rs` 主程序完全同一条路径，但把完整 `t` / 出错信息 / 逐步 trace
//! 打出来，供 `tools/compare.py` 与 Python oracle 对比。
//!
//! 用法：
//!   cargo run --release --bin sentinel-trace -- sample_challenge.json
//!   SENTINEL_TRACE_FILE=target/rs_writes.txt cargo run --release --bin sentinel-trace
//!
//! 输出（stdout）：
//!   steps=<n>
//!   t=<base64>
//!   err=<...>      （仅出错时）
//!   tlen=<len>
use base64::Engine;
use sentinel_rs::value::*;
use sentinel_rs::vm::Vm;

pub fn load_program(encoded: &str, key: &str) -> Result<Vec<Vec<Value>>, String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(encoded.as_bytes()))
        .map_err(|e| format!("base64: {e}"))?;
    let k = key.as_bytes();
    let plain: Vec<u8> = raw
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ k[i % k.len()])
        .collect();
    let text = String::from_utf8(plain).map_err(|e| format!("utf8: {e}"))?;
    let parsed: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("json: {e}"))?;
    let rows = parsed.as_array().ok_or("program 不是数组")?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let items = row.as_array().ok_or("指令不是数组")?;
        out.push(items.iter().map(from_json).collect::<Vec<_>>());
    }
    Ok(out)
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "sample_challenge.json".into());
    let text = std::fs::read_to_string(&path).expect("read challenge");
    let blob: serde_json::Value = serde_json::from_str(&text).expect("parse json");
    let p = blob.get("p").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let challenge = blob.get("challenge").cloned().unwrap_or_else(|| blob.clone());

    // 与 src/main.rs 完全一致的环境构造（参数目前不参与构建）
    let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36";
    let window = sentinel_rs::env::build_window(ua, "ja-JP", 1366, 768);
    let mut machine = Vm::new(window);
    // 与 tools/pyoracle.py 的同名环境变量保持一致，方便换一组 pin 再对比
    let pin = |key: &str, default: f64| -> f64 {
        std::env::var(key)
            .ok()
            .and_then(|v| v.trim().parse::<f64>().ok())
            .unwrap_or(default)
    };
    machine.set_pins(
        pin("SENTINEL_PIN_CLOCK_MS", 1_700_000_000_000.0),
        pin("SENTINEL_PIN_PERF_NOW", 15.5),
        pin("SENTINEL_PIN_RANDOM", 0.5),
    );
    let trace_on = std::env::var("SENTINEL_TRACE_FILE").is_ok();

    if let Some(dx) = challenge.pointer("/turnstile/dx").and_then(|v| v.as_str()) {
        let prog = load_program(dx, &p).expect("dx decode");
        // 与 Python 侧一致：key 在 trace 打开前写入，队列在打开后写入
        machine.set(16.0, Value::Str(std::rc::Rc::from(p.as_str())));
        machine.trace = trace_on;
        machine.load_queue(prog);
        match machine.run() {
            Ok(()) => {}
            Err(e) => println!("err={}", e.0),
        }
        if let Ok(file) = std::env::var("SENTINEL_TRACE_FILE") {
            std::fs::write(file, machine.trace_lines.join("\n") + "\n").expect("write trace");
        }
        if machine.err.is_some() && machine.out.is_none() {
            println!("steps={}", machine.steps);
            println!("err_field={}", machine.err.clone().unwrap_or_default());
            return;
        }
        println!("steps={}", machine.steps);
        println!("t={}", machine.out.clone().unwrap_or_default());
        println!("tlen={}", machine.out.as_ref().map(|s| s.len()).unwrap_or(0));
        if let Some(e) = &machine.err {
            println!("err_field={}", e);
        }
    }
}
