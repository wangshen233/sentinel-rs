//! SO token 自检：加载 `sample_challenge.json` 的 `challenge.so`，
//! 跑 collector → dispatch_behavior → snapshot，打印 `so` 的长度 / sha256 / steps。
//!
//! 运行：`cargo run --release --bin so_check`
//!
//! 输出（每行 `key value`，方便 `tools/so_compare.py` 解析）：
//!
//! ```text
//! steps 3728
//! so_len 608
//! sha256 bf336c37...
//! so TRsZBh8GCwwN...
//! ```
//!
//! 随机/时钟按 `tools/pyoracle.py` 的 pin 固定：`Date.now=1700000000000`、
//! `performance.now=15.5`（[`sentinel_rs::vm::Vm::new`] 的默认值）、
//! `random.random=0.5`（[`Rng::constant`]`(0.5)`）。
//!
//! 注意 `#[path]`：本程序直接把 `src/so.rs` 编进 bin，因此不依赖 `lib.rs` 是否
//! 已经写了 `pub mod so;`（lib 里加不加都能编）。
use std::path::PathBuf;

#[path = "../so.rs"]
#[allow(dead_code)] // bin 里只用到 mint_so_full / dispatch_behavior / so_state
mod so;

// so.rs 内部用 `crate::env` / `crate::value` / …（这样它在 lib 里也成立）；
// bin 侧在 crate 根挂同名别名，两种编译方式都能解析。
#[allow(unused_imports)]
use sentinel_rs::{env, mint, token, value, vm};

use sentinel_rs::token::{Profile, Rng};

/// Python oracle 的 `profile={}`（= `NavStub` / `VM._env` 的默认值）。
///
/// profile 里只有 navigator/screen/窗口尺寸这些字段会进 SO 采集，
/// 所以必须逐项对齐 Python 的默认值（尤其 UA 是 Chrome/152）。
fn oracle_profile() -> Profile {
    Profile {
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                     (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"
            .to_string(),
        language: "en-US".to_string(),
        languages: vec!["en-US".to_string(), "en".to_string()],
        timezone_name: "Asia/Tokyo".to_string(),
        timezone_offset: 540,
        tz_label: "Japan Standard Time".to_string(),
        screen_width: 1920,
        screen_height: 1080,
        hardware_concurrency: 8,
        platform: "Win32".to_string(),
        vendor: "Google Inc.".to_string(),
        device_memory: 8,
        device_pixel_ratio: 1.0,
        max_touch_points: 0,
        ua_brands: Vec::new(),
        ua_platform_version: String::new(),
        ua_arch: String::new(),
        ua_bitness: String::new(),
        is_mobile: false,
        page_time_origin_ms: 1_700_000_000_000.0 - 15.5,
    }
}

/// challenge 文件：优先当前目录，其次 crate 根（`cargo run` 从任意目录都能跑）。
fn challenge_path() -> PathBuf {
    let local = PathBuf::from("sample_challenge.json");
    if local.is_file() {
        return local;
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("sample_challenge.json")
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("[so_check] {err}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<i32, String> {
    let path = challenge_path();
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("读 {} 失败: {e}", path.display()))?;
    let blob: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("解析 challenge JSON 失败: {e}"))?;

    let p = blob
        .get("p")
        .and_then(|v| v.as_str())
        .ok_or("challenge 缺少 p")?;
    let so_block = blob
        .get("challenge")
        .and_then(|c| c.get("so"))
        .ok_or("challenge 缺少 so 块")?;
    let collector_dx = so_block
        .get("collector_dx")
        .and_then(|v| v.as_str())
        .ok_or("challenge.so 缺少 collector_dx")?;
    let snapshot_dx = so_block
        .get("snapshot_dx")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let profile = oracle_profile();
    let mut rng = Rng::constant(0.5);
    let out = so::mint_so_full(collector_dx, snapshot_dx, p, &profile, &mut rng)?;

    println!("steps {}", out.steps);
    println!("collector_steps {}", out.collector_steps);
    println!("dispatch_steps {}", out.dispatch_steps);
    println!("listeners {}", out.listeners.join(","));
    println!("so_len {}", out.so.len());
    println!("sha256 {}", hex(&sha256(out.so.as_bytes())));
    println!("so {}", out.so);

    if std::env::var("SENTINEL_SO_DEBUG").is_ok() {
        dump_state(collector_dx, p);
    }
    Ok(0)
}

/// 手搓一遍 collector → dispatch，把 window 上的 `__oai_so_*` 状态打到 stderr。
fn dump_state(collector_dx: &str, p: &str) {
    use sentinel_rs::value::Value;
    use std::rc::Rc;

    let profile = oracle_profile();
    let mut machine = sentinel_rs::mint::new_vm(&profile);
    machine.set(16.0, Value::Str(Rc::from(p)));
    let Ok(program) = sentinel_rs::mint::load_program(collector_dx, p) else {
        eprintln!("[debug] collector 解码失败");
        return;
    };
    machine.done = false;
    machine.out = None;
    machine.err = None;
    if let Err(e) = machine.run_program(program, p) {
        eprintln!("[debug] collector 失败: {}", e.0);
    }
    let mut rng = Rng::constant(0.5);
    so::dispatch_behavior(&mut machine, &profile, &mut rng, 0);
    for (key, value) in so::so_state(&machine) {
        eprintln!("state {} = {}", key, value);
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

// ---------------------------------------------------------------- SHA-256
//
// Cargo.toml 里没有 sha2（且本任务不允许改 Cargo.toml），所以这里自带一份。

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, v) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *slot = slot.wrapping_add(v);
        }
    }

    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(b"The quick brown fox jumps over the lazy dog")),
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        );
    }
}
