//! 真实指纹 + 固定 pin 下的 dx → t / so（供与 Python 逐字节对拍）。
use sentinel_rs::token::{self, Rng};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "sample_challenge.json".into());
    let want_so = args.iter().any(|a| a == "--so");
    let text = std::fs::read_to_string(&path).expect("read challenge");
    let blob: serde_json::Value = serde_json::from_str(&text).expect("parse json");
    let p = blob
        .get("p")
        .and_then(|v| v.as_str())
        .expect("p")
        .to_string();
    let turnstile = blob
        .pointer("/challenge/turnstile/dx")
        .or_else(|| blob.pointer("/turnstile/dx"))
        .and_then(|v| v.as_str())
        .expect("dx")
        .to_string();
    let fp = blob.get("fp").cloned().unwrap_or(serde_json::Value::Null);

    const NOW_MS: f64 = 1_793_036_746_210.0;
    const PERF: f64 = 15.5;
    let mut rng = Rng::constant(0.5);
    let profile = token::Profile::from_fingerprint(&fp, NOW_MS, &mut rng).expect("profile");

    if !want_so {
        let mut machine = sentinel_rs::mint::new_vm(&profile);
        machine.set_pins(NOW_MS, PERF, 0.5);
        let t = sentinel_rs::mint::mint_t_in(&mut machine, &turnstile, &p).expect("mint");
        println!("{t}");
        return;
    }

    let collector = blob
        .pointer("/challenge/so/collector_dx")
        .and_then(|v| v.as_str())
        .expect("collector_dx")
        .to_string();
    let snapshot = blob
        .pointer("/challenge/so/snapshot_dx")
        .and_then(|v| v.as_str())
        .expect("snapshot_dx")
        .to_string();

    let mut machine = sentinel_rs::mint::new_vm(&profile);
    machine.set_pins(NOW_MS, PERF, 0.5);
    sentinel_rs::mint::mint_t_in(&mut machine, &collector, &p).expect("collector");
    sentinel_rs::so::dispatch_behavior(&mut machine, &profile, &mut rng, 0);
    let prog = sentinel_rs::mint::load_program(&snapshot, &p).expect("snapshot prog");
    machine.done = false;
    machine.out = None;
    machine.err = None;
    machine.run_program(prog, &p).expect("snapshot");
    println!("{}", machine.out.clone().unwrap_or_default());
}
