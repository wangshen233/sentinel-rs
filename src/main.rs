//! sentinel-rs CLI：`mint`（sentinel token）+ `register`（注册流程骨架）。
//!
//! 用法见 `--help`。默认 **dry-run**：`register` 只构造并打印请求计划，不联网。

use anyhow::{bail, Context, Result};
use base64::Engine;
use sentinel_rs::flow::{self, RegisterConfig};
use sentinel_rs::value::*;
use sentinel_rs::vm::Vm;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    if let Err(err) = run() {
        eprintln!("错误: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() {
        print_help();
        return Ok(());
    }

    let command = argv[0].as_str();
    let rest = &argv[1..];

    match command {
        "-h" | "--help" | "help" => {
            print_help();
            Ok(())
        }
        "-V" | "--version" => {
            println!("sentinel-rs {VERSION}");
            Ok(())
        }
        "mint" => cmd_mint(rest),
        "register" => cmd_register(rest),
        other => {
            print_help();
            bail!("未知子命令: {other:?}（可选：mint / register / help）")
        }
    }
}

// ─────────────────────────── mint ───────────────────────────



fn cmd_mint(argv: &[String]) -> Result<()> {
    let mut file = String::from("sample_challenge.json");
    let mut p_override: Option<String> = None;
    let mut run_vm = false;
    let mut want_so = false;
    let mut oracle_env = false;
    let mut flow = flow::sentinel::FLOW_AUTHORIZE_CONTINUE.to_string();

    let mut iter = argv.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--file" | "-f" => {
                file = iter
                    .next()
                    .context("--file 需要一个路径参数")?
                    .to_string();
            }
            "--p" => {
                p_override = Some(iter.next().context("--p 需要一个 key 参数")?.to_string());
            }
            "--run-vm" => run_vm = true,
            "--so" => want_so = true,
            "--oracle-env" => oracle_env = true,
            "--flow" => {
                let raw = iter.next().context("--flow 需要一个名字")?.trim().to_string();
                if raw.is_empty() {
                    bail!("--flow 不能为空（例：--flow email_otp_validate）");
                }
                flow = raw;
            }
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            other => bail!("mint 未识别的参数: {other:?}"),
        }
    }

    let text = std::fs::read_to_string(&file)
        .with_context(|| format!("读取 challenge 文件失败: {file}"))?;
    let blob: serde_json::Value =
        serde_json::from_str(&text).with_context(|| format!("{file} 不是合法 JSON"))?;

    let p = p_override
        .or_else(|| blob.get("p").and_then(|v| v.as_str()).map(str::to_string))
        .unwrap_or_default();
    if p.is_empty() {
        bail!("{file} 里没有 p（XOR key），可用 --p 显式指定");
    }

    let dx = blob
        .pointer("/challenge/turnstile/dx")
        .or_else(|| blob.pointer("/turnstile/dx"))
        .or_else(|| blob.get("dx"))
        .and_then(|v| v.as_str())
        .context("文件里找不到 turnstile.dx")?;

    let program = load_program(dx, &p).map_err(anyhow::Error::msg)?;
    println!("challenge: {file}");
    println!("flow     : {flow}");
    println!("dx 解码成功：指令数 = {}", program.len());

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64() * 1000.0)
        .unwrap_or(0.0);
    let mut rng = sentinel_rs::token::Rng::System(rand::thread_rng());
    let fp = blob.get("fp").cloned().unwrap_or(serde_json::Value::Null);
    let profile = if fp.get("user_agent").is_some() {
        sentinel_rs::token::Profile::from_fingerprint(&fp, now_ms, &mut rng)
            .map_err(anyhow::Error::msg)?
    } else {
        sentinel_rs::token::Profile::new(
            &sentinel_rs::token::ProfileOptions::default(),
            now_ms,
            &mut rng,
        )
    };

    let t = if oracle_env {
        sentinel_rs::mint::mint_t_oracle(dx, &p).map_err(anyhow::Error::msg)?
    } else {
        sentinel_rs::mint::mint_t(dx, &p, &profile).map_err(anyhow::Error::msg)?
    };
    println!("t 长度 = {}", t.len());
    println!("{t}");

    // 文件里若带 challenge.token / did，就把真实头载荷也拼出来看一眼
    // （p 用 requirements token = 文件的 p；PoW 不要求 enforcement 时 Python 同样回退它）。
    let challenge = flow::sentinel::Challenge::from_blob(&blob).ok();
    let c_value = challenge.as_ref().map(|c| c.c_value()).unwrap_or_default();
    let did = blob
        .get("did")
        .or_else(|| blob.get("device_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if c_value.is_empty() || did.is_empty() {
        println!("（文件里缺 challenge.token / did，跳过 sentinel 头载荷预览）");
    } else {
        println!(
            "openai-sentinel-token = {}",
            flow::sentinel::token_payload_json(&p, &t, &c_value, &did, &flow)
        );
    }

    if want_so {
        print_so(&blob, challenge.as_ref(), &p, &profile, &c_value, &did, &flow);
    }

    if run_vm {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36";
        let window = sentinel_rs::env::build_window(ua, "ja-JP", 1366, 768);
        let mut machine = Vm::new(window);
        match machine.run_program(program, &p) {
            Ok(()) => {}
            Err(err) => println!("VM 执行错误 = {}", err.0),
        }
        println!(
            "VM: steps = {}  t_len = {}  err = {:?}",
            machine.steps,
            machine.out.as_ref().map(|s| s.len()).unwrap_or(0),
            machine.err
        );
        if let Some(t) = &machine.out {
            println!("t head = {}", &t[..t.len().min(80)]);
        }
    }

    Ok(())
}

/// `--so`：跑 SO 的 collector + snapshot，打印 `openai-sentinel-so-token` 载荷。
///
/// so 依赖（`mint::mint_so` / `src/so.rs`）未就绪时**只打印明确提示并正常返回**
/// （exit 0），不把整个 mint 命令拖挂。
fn print_so(
    blob: &serde_json::Value,
    challenge: Option<&flow::sentinel::Challenge>,
    p: &str,
    profile: &sentinel_rs::token::Profile,
    c_value: &str,
    did: &str,
    flow_name: &str,
) {
    println!("-- so --");
    let Some(challenge) = challenge else {
        println!("文件里没有 challenge 块，无法判断 so 依赖；跳过");
        return;
    };
    if !challenge.so_required() {
        println!("challenge.so.required = false：flow={flow_name} 这次不需要 SO token，跳过");
        return;
    }
    let Some(collector) = challenge.collector_dx() else {
        println!("challenge.so.required = true 但没有 collector_dx：没有 SO 程序可跑，跳过");
        return;
    };
    let snapshot = challenge.snapshot_dx();
    println!(
        "so.required = true  collector_dx = {} 字符  snapshot_dx = {}",
        collector.len(),
        snapshot
            .map(|s| format!("{} 字符", s.len()))
            .unwrap_or_else(|| "<无>".to_string())
    );
    match flow::sentinel::mint_so_best_effort(collector, snapshot, p, profile) {
        flow::sentinel::SoMint::Ready(so) => {
            println!("so 长度 = {}", so.len());
            println!("{so}");
            if !c_value.is_empty() && !did.is_empty() {
                println!(
                    "openai-sentinel-so-token = {}",
                    flow::sentinel::so_payload_json(&so, c_value, did, flow_name)
                );
            } else {
                println!("（文件里缺 challenge.token / did，跳过 SO 头载荷预览）");
            }
        }
        flow::sentinel::SoMint::NotReady(reason) => {
            println!("SO 生成未执行：{reason}");
            println!("提示：拿不到 SO token 时主 token 仍可用（与 Python 一致，不带 SO 头）；exit 0。");
            let _ = blob; // 保留参数，方便落地后直接读更多 so 字段
        }
        flow::sentinel::SoMint::Skipped => println!("SO 程序为空，跳过"),
    }
}

/// base64(XOR(JSON, key)) → 指令数组（dx 的编码方式，与 Python 版一致）。
fn load_program(encoded: &str, key: &str) -> Result<Vec<Vec<Value>>, String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(encoded.as_bytes()))
        .map_err(|e| format!("base64: {e}"))?;
    let k = key.as_bytes();
    if k.is_empty() {
        return Err("p（XOR key）为空".into());
    }
    let plain: Vec<u8> = raw.iter().enumerate().map(|(i, b)| b ^ k[i % k.len()]).collect();
    let text = String::from_utf8(plain).map_err(|e| format!("utf8: {e}"))?;
    let parsed: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("json: {e}"))?;
    let rows = parsed.as_array().ok_or("program 不是数组")?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let items = row.as_array().ok_or("指令不是数组")?;
        out.push(items.iter().map(from_json).collect::<Vec<Value>>());
    }
    Ok(out)
}

// ─────────────────────────── register ───────────────────────────

fn cmd_register(argv: &[String]) -> Result<()> {
    let _ = dotenvy::dotenv();

    let mut cfg = RegisterConfig::from_env().context("读取注册配置失败")?;
    let mut concurrency: usize = 1;

    let mut iter = argv.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-n" | "--count" => {
                let raw = iter.next().context("-n/--count 需要一个数字")?;
                let count: usize = raw
                    .parse()
                    .with_context(|| format!("-n/--count 解析失败: {raw:?}"))?;
                if count == 0 {
                    bail!("-n/--count 必须 >= 1");
                }
                cfg.count = count;
            }
            "--db" => {
                cfg.db_path = std::path::PathBuf::from(iter.next().context("--db 需要一个路径")?);
            }
            "--proxy" => {
                let raw = iter.next().context("--proxy 需要一个地址")?.to_string();
                flow::http::normalize_proxy_url(&raw)?;
                cfg.proxy = Some(raw);
            }
            "--2fa" => cfg.enable_2fa = true,
            "--concurrency" | "-c" => {
                let raw = iter.next().context("--concurrency 需要一个数字")?;
                concurrency = raw
                    .parse()
                    .with_context(|| format!("--concurrency 解析失败: {raw:?}"))?;
                if concurrency == 0 {
                    bail!("--concurrency 必须 >= 1");
                }
            }
            "--live" => cfg.dry_run = false,
            "--dry-run" => cfg.dry_run = true,
            "--preflight" => {
                // 只验证 authorize 会话建立（warmup → signin → authorize init），
                // 不领邮箱、不注册；等价于 live 模式但不消耗邮箱。
                cfg.preflight = true;
                cfg.dry_run = false;
            }
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            other => bail!("register 未识别的参数: {other:?}"),
        }
    }

    init_tracing();

    // 单账号：先把本次要用的设备指纹定下来，配置里打印的就是这次真正使用的那一套。
    // 多账号（-n > 1）留给 register_once 逐账号生成，避免 N 个号共用一张画像。
    if cfg.fingerprint.is_none() && cfg.count == 1 {
        cfg.fingerprint = cfg.resolve_fingerprint();
    }

    println!("== 注册配置 ==");
    println!("  模式      : {}", if cfg.dry_run { "dry-run（不联网）" } else { "LIVE（真实联网注册）" });
    println!("  数量      : {}", cfg.count);
    println!("  代理      : {}", cfg.proxy.as_deref().unwrap_or("<直连>"));
    println!(
        "  邮箱 API  : {}",
        cfg.email_api
            .as_ref()
            .map(|api| api.base_url.as_str())
            .unwrap_or("<未配置：REG_MAIL_API_BASE_URL>")
    );
    println!("  2FA       : {}", if cfg.enable_2fa { "enroll+activate" } else { "关闭" });
    println!("  数据库    : {}", cfg.db_path.display());
    println!("  取码超时  : {}s（间隔 {}s）", cfg.otp_max_wait_secs, cfg.otp_poll_interval_secs);
    println!("  指纹      : {}", fingerprint_line(&cfg));

    cfg.require_live_prerequisites()?;

    if cfg.preflight {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("创建 tokio runtime 失败")?;
        println!("\n-- preflight：只验证 authorize 会话（不领邮箱 / 不注册）--");
        let lines = runtime
            .block_on(flow::preflight_authorize(&cfg))
            .context("preflight 失败")?;
        for line in lines {
            println!("  {line}");
        }
        return Ok(());
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("创建 tokio runtime 失败")?;

    let mut ok = 0usize;
    let mut failed = 0usize;

    if concurrency > 1 {
        println!("\n-- 并发模式：{concurrency} 并发，共 {} 个 --", cfg.count);
        let (okn, failedn) = runtime.block_on(async {
            let mut ok = 0usize;
            let mut failed = 0usize;
            let mut done = 0usize;
            while done < cfg.count {
                let batch = (cfg.count - done).min(concurrency);
                let mut set: tokio::task::JoinSet<anyhow::Result<flow::RegistrationOutcome>> =
                    tokio::task::JoinSet::new();
                for _ in 0..batch {
                    let c = cfg.clone();
                    set.spawn(async move { flow::register_once(&c).await });
                }
                for _ in 0..batch {
                    done += 1;
                    match set.join_next().await {
                        Some(Ok(Ok(o))) => {
                            ok += 1;
                            println!("[{done}/{}] OK   {}", cfg.count, o.email);
                        }
                        Some(Ok(Err(err))) => {
                            failed += 1;
                            println!("[{done}/{}] FAIL {err:#}", cfg.count);
                        }
                        Some(Err(err)) => {
                            failed += 1;
                            println!("[{done}/{}] JOIN-ERR {err}", cfg.count);
                        }
                        None => break,
                    }
                }
            }
            (ok, failed)
        });
        ok = okn;
        failed = failedn;
        println!("\n== 汇总 ==  成功 {ok} / 失败 {failed} / 总计 {}", cfg.count);
        if failed > 0 && ok == 0 {
            bail!("全部 {failed} 次注册均失败");
        }
        return Ok(());
    }

    for index in 1..=cfg.count {
        println!("\n-- [{index}/{}] --", cfg.count);
        match runtime.block_on(flow::register_once(&cfg)) {
            Ok(outcome) => {
                ok += 1;
                if outcome.dry_run {
                    println!("dry-run 计划（{} 步，均未发送）：", outcome.plan.len());
                    for (i, line) in outcome.plan.iter().enumerate() {
                        println!("  {:>2}. {}", i + 1, line);
                    }
                    println!("占位身份: {}（密码长度 {}）", outcome.email, outcome.password.len());
                } else {
                    println!(
                        "注册完成: {}  account_id={:?}  access_token={}  2fa={}",
                        outcome.email,
                        outcome.account_id,
                        if outcome.access_token.is_some() { "有" } else { "无" },
                        outcome.totp_secret.is_some()
                    );
                }
            }
            Err(err) => {
                failed += 1;
                eprintln!("本次失败: {err:#}");
            }
        }
    }

    println!("\n== 汇总 ==  成功 {ok} / 失败 {failed} / 总计 {}", cfg.count);
    if failed > 0 && ok == 0 {
        bail!("全部 {failed} 次注册均失败");
    }
    Ok(())
}

/// 配置打印里的「指纹」一行：`<版本> / <平台> / <时区> / <屏幕>/<dpr> / fp=<id>`。
///
/// 多账号 / 显式覆盖时不打印具体值（那种情况下每个账号各有一套或干脆固定）。
fn fingerprint_line(cfg: &RegisterConfig) -> String {
    match &cfg.fingerprint {
        Some(fp) => fp.summary(),
        None if cfg.count > 1 => format!(
            "每个账号独立生成（共 {} 套，可用 SENTINEL_FP_SEED 固定）",
            cfg.count
        ),
        None => "固定（SENTINEL_USER_AGENT / SENTINEL_ACCEPT_LANGUAGE 显式覆盖）".to_string(),
    }
}

fn init_tracing() {
    let level = match std::env::var("SENTINEL_LOG")
        .unwrap_or_else(|_| "info".to_string())
        .to_ascii_lowercase()
        .as_str()
    {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        "off" => return,
        _ => tracing::Level::INFO,
    };
    let _ = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .try_init();
}

// ─────────────────────────── help ───────────────────────────

fn print_help() {
    println!(
        r#"sentinel-rs {VERSION} — Sentinel token 生成 + 注册流程骨架

用法:
  sentinel-rs <命令> [选项]

命令:
  mint        解码 challenge，生成 sentinel token（可选同时生成 SO token）
  register    跑注册流程；默认 dry-run，只打印计划（含真实 sentinel 步骤），不联网
  help        显示本帮助（等价 --help / -h）

全局:
  -h, --help      显示帮助
  -V, --version   显示版本

mint 选项:
  --file <PATH>   challenge JSON 路径（默认 sample_challenge.json）
  --p <KEY>       覆盖文件里的 p（dx 的 XOR key）
  --flow <NAME>   sentinel flow 名（默认 authorize_continue；另有 email_otp /
                  email_otp_validate / username_password_create / oauth_create_account）
  --so            额外生成 SO token（openai-sentinel-so-token 载荷）
  --run-vm        解码后额外用内置 VM 跑一遍 dx（打印 steps / t_len）

register 选项:
  -n, --count <N> 注册数量（默认取 SENTINEL_COUNT，缺省 1）
  --db <PATH>     SQLite 路径（默认 data/sentinel-rs.db）
  --proxy <URL>   代理，支持 host:port 或 http://user:pass@host:port
  --2fa           注册后 enroll+activate TOTP
  --dry-run       只构造请求计划（默认行为）
  --preflight     只验证 authorize 会话（warmup → signin → authorize init），
                  不领邮箱、不注册、不发码；用来确认 live 链路状态是否正常
  --live          真实联网注册（危险：会真的建号，需自备邮箱 API 与 sentinel token 源）

环境变量（.env 亦可）:
  SENTINEL_PROXY / HTTPS_PROXY / ALL_PROXY   代理
  REG_MAIL_API_BASE_URL / REG_MAIL_API_TOKEN  邮箱取码 API（token 可选，见 README）
  REG_MAIL_ALLOW_INSECURE                     1 放行回环 http://（本地自建 / mock）
  SENTINEL_COUNT / REGISTER_COUNT            默认数量
  SENTINEL_DB_PATH                           默认数据库路径
  SENTINEL_ENABLE_2FA                        1/true 开启 2FA
  OTP_MAX_WAIT / OTP_POLL_INTERVAL           取码超时 / 轮询间隔（秒）
  SENTINEL_LIVE_REGISTER                     1 才允许真实联网注册
  SENTINEL_USER_AGENT / SENTINEL_ACCEPT_LANGUAGE  显式指定 UA / 语言（给定时不做随机指纹）
  SENTINEL_FP_SEED                           设备指纹 seed（同 seed 可复现整套指纹）
  SENTINEL_FP_COUNTRY                        强制指纹区域（JP / GB / DE …）
  SENTINEL_LOG                               trace/debug/info/warn/error/off

示例:
  sentinel-rs --help
  sentinel-rs mint --file sample_challenge.json
  sentinel-rs mint --file sample_challenge.json --so
  sentinel-rs mint --file sample_challenge.json --so --flow email_otp_validate
  sentinel-rs register -n 1
  sentinel-rs register -n 3 --2fa --dry-run

注意:
  * register 默认 dry-run：不联网、不发邮件、不写真实凭证。
  * --live 需要邮箱取码 API 配置（REG_MAIL_API_BASE_URL，契约见 README）；\
 sentinel token 由 src/flow/sentinel.rs 生成。
  * SO token 依赖 mint_so（src/so.rs），未就绪时 mint --so 只打印提示并 exit 0。
"#
    );
}
