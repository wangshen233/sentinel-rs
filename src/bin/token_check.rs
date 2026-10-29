//! token 层 parity 自检：加载 `tests/token_expected.json`（由 `tools/token_parity.py`
//! 用权威 Python 实现生成），逐字段 / 逐字节比对 `sentinel_rs::token` 的输出。
//!
//! 运行：`cargo run --release --bin token_check`
//! 输出末行 `equal=True` 表示完全一致；不一致时打印差异并 `equal=False`（退出码 1）。

use std::path::{Path, PathBuf};

use serde_json::Value;

use sentinel_rs::token::{
    build_config, enforcement_token, fnv1a, js_date, py_float_repr, py_round_17, py_round_int,
    requirements_token, Config, Profile, ProfileOptions, Rng, TokenCtx,
};

// ------------------------------------------------------------------ 报告器

struct Checker {
    checks: usize,
    fails: Vec<String>,
}

impl Checker {
    fn new() -> Self {
        Checker {
            checks: 0,
            fails: Vec::new(),
        }
    }

    fn eq<T: PartialEq + std::fmt::Debug>(&mut self, what: &str, got: T, want: T) {
        self.checks += 1;
        if got != want {
            self.fails
                .push(format!("{}: got {:#?} want {:#?}", what, got, want));
        }
    }

    fn eq_str(&mut self, what: &str, got: &str, want: &str) {
        self.checks += 1;
        if got != want {
            let (i, g, w) = first_diff(got, want);
            self.fails.push(format!(
                "{}: 首个差异 @byte {} got {:?} want {:?}\n      got_len={} want_len={}",
                what,
                i,
                g,
                w,
                got.len(),
                want.len()
            ));
        }
    }
}

fn first_diff(got: &str, want: &str) -> (usize, String, String) {
    let g = got.as_bytes();
    let w = want.as_bytes();
    let idx = g
        .iter()
        .zip(w.iter())
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| g.len().min(w.len()));
    let lo = idx.saturating_sub(20);
    let hi_g = (idx + 30).min(got.len());
    let hi_w = (idx + 30).min(want.len());
    (
        idx,
        got.get(lo..hi_g).unwrap_or("<边界>").to_string(),
        want.get(lo..hi_w).unwrap_or("<边界>").to_string(),
    )
}

// ------------------------------------------------------------------ 构造器

fn make_rng(kind: &str, meta: &Value) -> Rng {
    match kind {
        "const" => Rng::constant(meta["const_value"].as_f64().expect("const_value")),
        "lcg" => Rng::lcg(meta["lcg"]["seed"].as_u64().expect("lcg seed")),
        other => panic!("未知 rng kind: {}", other),
    }
}

fn options_from(meta: &Value) -> ProfileOptions {
    let o = &meta["explicit_profile_options"];
    let s = |k: &str| -> Option<String> {
        match o.get(k) {
            Some(Value::String(v)) => Some(v.clone()),
            _ => None,
        }
    };
    ProfileOptions {
        user_agent: s("user_agent"),
        screen: s("screen"),
        lang: s("lang"),
        languages: s("languages"),
        platform: s("platform"),
        vendor: s("vendor"),
        hardware_concurrency: o.get("hardware_concurrency").and_then(|v| v.as_i64()),
        device_memory: o.get("device_memory").and_then(|v| v.as_i64()),
        device_pixel_ratio: o.get("device_pixel_ratio").and_then(|v| v.as_f64()),
        timezone: s("timezone"),
    }
}

fn build_profile(
    case: &Value,
    fp: &Value,
    meta: &Value,
    now_ms: f64,
    rng: &mut Rng,
) -> Profile {
    match case["profile_kind"].as_str().expect("profile_kind") {
        "fingerprint" => Profile::from_fingerprint(fp, now_ms, rng).expect("profile from fp"),
        "explicit" => {
            let opts = options_from(meta);
            Profile::new(&opts, now_ms, rng)
        }
        other => panic!("未知 profile_kind: {}", other),
    }
}

// ---------------------------------------------------------------- 各类比对

fn check_profile(chk: &mut Checker, tag: &str, p: &Profile, want: &Value) {
    let w = |k: &str| -> String { want[k].as_str().unwrap_or("<非字符串>").to_string() };
    chk.eq_str(&format!("{}.user_agent", tag), &p.user_agent, &w("user_agent"));
    chk.eq_str(&format!("{}.language", tag), &p.language, &w("language"));
    let want_langs: Vec<String> = want["languages"]
        .as_array()
        .expect("languages")
        .iter()
        .map(|v| v.as_str().unwrap_or("").to_string())
        .collect();
    chk.eq(&format!("{}.languages", tag), p.languages.clone(), want_langs);
    chk.eq_str(
        &format!("{}.timezone_name", tag),
        &p.timezone_name,
        &w("timezone_name"),
    );
    chk.eq(
        &format!("{}.timezone_offset", tag),
        p.timezone_offset as i64,
        want["timezone_offset"].as_i64().expect("tz offset"),
    );
    chk.eq_str(&format!("{}.tz_label", tag), &p.tz_label, &w("tz_label"));
    chk.eq(
        &format!("{}.screen_width", tag),
        p.screen_width,
        want["screen_width"].as_i64().expect("sw"),
    );
    chk.eq(
        &format!("{}.screen_height", tag),
        p.screen_height,
        want["screen_height"].as_i64().expect("sh"),
    );
    chk.eq(
        &format!("{}.hardware_concurrency", tag),
        p.hardware_concurrency,
        want["hardware_concurrency"].as_i64().expect("hc"),
    );
    chk.eq_str(&format!("{}.platform", tag), &p.platform, &w("platform"));
    chk.eq_str(&format!("{}.vendor", tag), &p.vendor, &w("vendor"));
    chk.eq(
        &format!("{}.device_memory", tag),
        p.device_memory,
        want["device_memory"].as_i64().expect("dm"),
    );
    chk.eq_str(
        &format!("{}.device_pixel_ratio", tag),
        &py_float_repr(p.device_pixel_ratio),
        want["device_pixel_ratio_repr"].as_str().expect("dpr repr"),
    );
    chk.eq(
        &format!("{}.max_touch_points", tag),
        p.max_touch_points,
        want["max_touch_points"].as_i64().expect("mtp"),
    );
    let want_brands: Vec<(String, String)> = want["ua_brands"]
        .as_array()
        .expect("ua_brands")
        .iter()
        .map(|b| {
            (
                b["brand"].as_str().unwrap_or("").to_string(),
                b["version"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    let got_brands: Vec<(String, String)> = p
        .ua_brands
        .iter()
        .map(|b| (b.brand.clone(), b.version.clone()))
        .collect();
    chk.eq(&format!("{}.ua_brands", tag), got_brands, want_brands);
    chk.eq_str(
        &format!("{}.ua_platform_version", tag),
        &p.ua_platform_version,
        &w("ua_platform_version"),
    );
    chk.eq_str(&format!("{}.ua_arch", tag), &p.ua_arch, &w("ua_arch"));
    chk.eq_str(&format!("{}.ua_bitness", tag), &p.ua_bitness, &w("ua_bitness"));
    chk.eq(
        &format!("{}.is_mobile", tag),
        p.is_mobile,
        want["is_mobile"].as_bool().expect("is_mobile"),
    );
    // 浮点用 CPython repr 文本比较 ⇒ 等价于逐位相等
    // （注意：serde_json 解析 JSON 数字可能差 1 ulp，所以期望值存的是 repr 文本，
    //   这里用 Rust 正确舍入的 str::parse 还原，再交给 py_float_repr 输出。）
    chk.eq_str(
        &format!("{}.page_time_origin_ms", tag),
        &py_float_repr(p.page_time_origin_ms),
        want["page_time_origin_ms_repr"]
            .as_str()
            .expect("origin repr"),
    );
}

fn check_config(chk: &mut Checker, tag: &str, cfg: &Config, want: &Value) {
    chk.eq(&format!("{}.len", tag), cfg.len(), 25usize);
    chk.eq_str(
        &format!("{}.json", tag),
        &cfg.to_json_string(),
        want["json"].as_str().expect("config json"),
    );
    let want_fields: Vec<String> = want["fields"]
        .as_array()
        .expect("fields")
        .iter()
        .map(|v| v.as_str().unwrap_or("").to_string())
        .collect();
    let got_fields = cfg.fields_json();
    chk.eq(&format!("{}.fields.len", tag), got_fields.len(), want_fields.len());
    for (i, (got, want)) in got_fields.iter().zip(want_fields.iter()).enumerate() {
        chk.eq_str(&format!("{}.field[{}]", tag, i), got, want);
    }
}

fn main() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let expected_path = manifest.join("tests").join("token_expected.json");
    let sample_path = manifest.join("sample_challenge.json");

    println!("== sentinel-rs token parity check ==");
    println!("expected : {}", expected_path.display());
    println!("challenge: {}", sample_path.display());

    let expected_text = std::fs::read_to_string(&expected_path).unwrap_or_else(|e| {
        panic!(
            "读不到 {}: {}（先运行 python tools/token_parity.py）",
            expected_path.display(),
            e
        )
    });
    let expected: Value = serde_json::from_str(&expected_text).expect("parse expected json");
    let sample_text =
        std::fs::read_to_string(&sample_path).unwrap_or_else(|e| panic!("读不到 challenge: {}", e));
    let sample: Value = serde_json::from_str(&sample_text).expect("parse sample challenge");

    let meta = &expected["meta"];
    let fp = &expected["fp"];
    let challenge = sample.get("challenge").expect("sample.challenge");
    let now_ms = meta["now_ms_repr"]
        .as_str()
        .expect("now_ms_repr")
        .parse::<f64>()
        .expect("now_ms");
    let sid = meta["sid"].as_str().expect("sid");
    let uuid_seed = meta["uuid_seed"].as_str().expect("uuid_seed");

    let mut chk = Checker::new();

    // ---------------------------------------------------------- 主场景
    for case in expected["cases"].as_array().expect("cases") {
        let name = case["name"].as_str().expect("case name");
        let rng_kind = case["rng"].as_str().expect("rng");
        println!("\n-- {} (rng={}, profile={})", name, rng_kind, case["profile_kind"]);

        // 1) profile
        let mut rng = make_rng(rng_kind, meta);
        let profile = build_profile(case, fp, meta, now_ms, &mut rng);
        check_profile(&mut chk, &format!("{}.profile", name), &profile, &case["profile"]);

        // 2) build_config
        let mut rng = make_rng(rng_kind, meta);
        let profile_cfg = build_profile(case, fp, meta, now_ms, &mut rng);
        let cfg = build_config(&profile_cfg, sid, now_ms, &mut rng);
        check_config(&mut chk, &format!("{}.config", name), &cfg, &case["config"]);

        // 3) requirements_token
        let mut ctx = TokenCtx::new(now_ms, make_rng(rng_kind, meta));
        let profile_req = build_profile(case, fp, meta, now_ms, &mut ctx.rng);
        let req = requirements_token(&profile_req, sid, uuid_seed, &mut ctx)
            .unwrap_or_else(|e| panic!("requirements_token 失败: {}", e));
        chk.eq_str(
            &format!("{}.requirements.token", name),
            &req,
            case["requirements"]["token"].as_str().expect("req token"),
        );
        let body = req.trim_start_matches("gAAAAAC").trim_end_matches("~S");
        let decoded = decode_b64(body);
        chk.eq_str(
            &format!("{}.requirements.embedded_json", name),
            &decoded,
            case["requirements"]["embedded_json"]
                .as_str()
                .expect("req json"),
        );
        let req_cfg: Value = serde_json::from_str(&decoded).expect("req cfg json");
        chk.eq(
            &format!("{}.requirements.attempt", name),
            req_cfg[3].as_i64(),
            case["requirements"]["attempt"].as_i64(),
        );
        chk.eq(
            &format!("{}.requirements.elapsed_ms", name),
            req_cfg[9].as_i64(),
            case["requirements"]["elapsed_ms"].as_i64(),
        );

        // 4) enforcement_token
        let mut ctx = TokenCtx::new(now_ms, make_rng(rng_kind, meta));
        let profile_enf = build_profile(case, fp, meta, now_ms, &mut ctx.rng);
        let enf = enforcement_token(challenge, &profile_enf, sid, &mut ctx)
            .unwrap_or_else(|e| panic!("enforcement_token 失败: {}", e))
            .expect("enforcement_token 返回 None");
        chk.eq_str(
            &format!("{}.enforcement.token", name),
            &enf,
            case["enforcement"]["token"].as_str().expect("enf token"),
        );
        let body = enf.trim_start_matches("gAAAAAB").trim_end_matches("~S");
        let decoded = decode_b64(body);
        chk.eq_str(
            &format!("{}.enforcement.embedded_json", name),
            &decoded,
            case["enforcement"]["embedded_json"]
                .as_str()
                .expect("enf json"),
        );
        let enf_cfg: Value = serde_json::from_str(&decoded).expect("enf cfg json");
        chk.eq(
            &format!("{}.enforcement.attempt", name),
            enf_cfg[3].as_i64(),
            case["enforcement"]["attempt"].as_i64(),
        );
        chk.eq(
            &format!("{}.enforcement.elapsed_ms", name),
            enf_cfg[9].as_i64(),
            case["enforcement"]["elapsed_ms"].as_i64(),
        );

        println!(
            "   cfg_len={} req[attempt={} elapsed={}] enf[attempt={} elapsed={}] req_len={} enf_len={}",
            cfg.to_json_string().len(),
            req_cfg[3],
            req_cfg[9],
            enf_cfg[3],
            enf_cfg[9],
            req.len(),
            enf.len()
        );
        println!("   req token  = {}", &req[..req.len().min(72)]);
        println!("   enf token  = {}", &enf[..enf.len().min(72)]);
    }

    // ------------------------------------------------------------ fnv1a
    println!("\n-- fnv1a");
    for c in expected["fnv_cases"].as_array().expect("fnv_cases") {
        let input = c["input"].as_str().expect("input");
        let got = fnv1a(input);
        chk.eq_str(
            &format!("fnv1a({:?})", truncate(input, 28)),
            &got,
            c["hash"].as_str().expect("hash"),
        );
    }
    println!("   {} 组全部比对", expected["fnv_cases"].as_array().unwrap().len());

    // ------------------------------------------------- 浮点 repr / round17
    println!("\n-- float repr + round(x,17)");
    for c in expected["float_cases"].as_array().expect("float_cases") {
        let raw = c["raw"].as_str().expect("raw");
        let x: f64 = raw.parse().expect("parse raw");
        chk.eq_str(&format!("repr({})", raw), &py_float_repr(x), c["repr_raw"].as_str().expect("repr_raw"));
        let r17 = py_round_17(x);
        chk.eq_str(&format!("repr(round({},17))", raw), &py_float_repr(r17), c["round17"].as_str().expect("round17"));
        chk.eq_str(&format!("json(round({},17))", raw), &py_float_repr(r17), c["json17"].as_str().expect("json17"));
    }
    println!(
        "   {} 组全部比对",
        expected["float_cases"].as_array().unwrap().len()
    );

    // ------------------------------------------------------ round(x) 取整
    println!("\n-- round(x) -> int");
    for c in expected["round_int_cases"].as_array().expect("round_int") {
        let raw = c["raw"].as_str().expect("raw");
        let x: f64 = raw.parse().expect("parse raw");
        chk.eq(
            &format!("round({})", raw),
            py_round_int(x),
            c["round"].as_i64().expect("round"),
        );
    }
    println!(
        "   {} 组全部比对",
        expected["round_int_cases"].as_array().unwrap().len()
    );

    // ------------------------------------------------------------ 日期串
    println!("\n-- js_date");
    let mut seed_rng = Rng::constant(0.5);
    for c in expected["date_cases"].as_array().expect("date_cases") {
        let off = c["offset_minutes"].as_i64().expect("offset") as i32;
        let ms = c["now_ms_repr"]
            .as_str()
            .expect("now_ms_repr")
            .parse::<f64>()
            .expect("now_ms");
        let label = c["tz_label"].as_str().expect("label");
        let mut p = Profile::new(&ProfileOptions::default(), now_ms, &mut seed_rng);
        p.timezone_offset = off;
        p.tz_label = label.to_string();
        let got = js_date(&p, ms);
        chk.eq_str(
            &format!("js_date(offset={}, now={})", off, ms),
            &got,
            c["out"].as_str().expect("out"),
        );
    }
    println!(
        "   {} 组全部比对",
        expected["date_cases"].as_array().unwrap().len()
    );

    // -------------------------------------------------------------- 汇总
    println!("\n== 汇总: checks={} failed={}", chk.checks, chk.fails.len());
    if !chk.fails.is_empty() {
        println!("-- 失败明细（最多 25 条）--");
        for f in chk.fails.iter().take(25) {
            println!("  {}", f);
        }
        println!("equal=False");
        std::process::exit(1);
    }
    println!("equal=True");
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let t: String = s.chars().take(n).collect();
        format!("{}…", t)
    }
}

fn decode_b64(s: &str) -> String {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .unwrap_or_else(|e| panic!("base64 解码失败: {}", e));
    String::from_utf8(bytes).expect("base64 内容不是 UTF-8")
}

#[allow(dead_code)]
fn unused(_p: &Path) {}
