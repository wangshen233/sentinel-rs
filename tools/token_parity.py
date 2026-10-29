# -*- coding: utf-8 -*-
"""token 层 parity oracle：用权威 Python 实现生成 tests/token_expected.json。

固定 random / time / uuid / datetime 之后，Python 侧（sentinel_py.py）的
build_config / requirements_token / enforcement_token 完全确定，Rust 侧
（src/bin/token_check.rs）加载同一份期望值逐字节比对。

用法：
    python tools/token_parity.py

可由环境变量 SENTINEL_PY_DIR 指向纯 Python Sentinel 目录（默认已给出）。
"""
from __future__ import annotations

import base64
import json
import os
import random as py_random
import sys
import uuid as py_uuid
from datetime import datetime as RealDatetime
from datetime import timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Python oracle 目录只从环境变量读，没有绝对默认值。
_ORACLE = os.environ.get("SENTINEL_PY_DIR") or os.environ.get("SENTINEL_ORACLE_DIR")
if not _ORACLE:
    sys.exit(
        "需要设置 SENTINEL_PY_DIR（或 SENTINEL_ORACLE_DIR）指向 Python oracle 目录"
        "（含 sentinel_py.py 的那个目录）"
    )
ORACLE_DIR = Path(_ORACLE)
sys.path.insert(0, str(ORACLE_DIR))

import sentinel_py as sp  # noqa: E402

# ---------------------------------------------------------------- 固定输入
NOW_MS = 1793036746210.0          # = 2026-10-26T17:45:46.210Z（样例 challenge 的时刻）
NOW_SEC = NOW_MS / 1000.0
SID = "55526215-419e-464b-bd75-0121d6f3bee1"          # 样例里的 instance sid
UUID_SEED = "9f2c1d34-5a6b-4c7d-8e9f-0a1b2c3d4e5f"    # requirements_token 的 PoW seed
CONST_VALUE = 0.5
LCG_SEED = 20261027
LCG_A = 1103515245
LCG_C = 12345
LCG_MOD = 2147483648  # 2**31


# ------------------------------------------------------- 可替换的 random/time
class ConstRandom:
    """random.random() 恒为 0.5；choice/uniform 按同一规则推导。"""

    kind = "const"

    def random(self):
        return CONST_VALUE

    def uniform(self, a, b):
        return a + (b - a) * self.random()

    def choice(self, seq):
        return seq[int(self.random() * len(seq))]


class LcgRandom:
    """确定性 LCG：state = (A*state + C) mod 2**31；u = state / 2**31。"""

    kind = "lcg"

    def __init__(self, seed=LCG_SEED):
        self.state = seed

    def random(self):
        self.state = (LCG_A * self.state + LCG_C) % LCG_MOD
        return self.state / float(LCG_MOD)

    def uniform(self, a, b):
        return a + (b - a) * self.random()

    def choice(self, seq):
        return seq[int(self.random() * len(seq))]


class FrozenTime:
    def __init__(self, ms):
        self.ms = ms

    def time(self):
        return self.ms / 1000.0

    def sleep(self, *_a, **_k):
        pass


class FrozenDatetime:
    _dt = None

    @classmethod
    def now(cls, tz=None):
        return cls._dt.astimezone(tz) if tz is not None else cls._dt

    @classmethod
    def set_ms(cls, ms):
        cls._dt = RealDatetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)


class FrozenUuid:
    def __init__(self, value):
        self.value = py_uuid.UUID(value)

    def uuid4(self):
        return self.value


def install_fakes(rng):
    sp.random = rng
    sp.time = FrozenTime(NOW_MS)
    sp.datetime = FrozenDatetime
    sp.uuid = FrozenUuid(UUID_SEED)
    FrozenDatetime.set_ms(NOW_MS)


def make_rng(kind):
    return ConstRandom() if kind == "const" else LcgRandom()


# ------------------------------------------------------------------ 工具
def dumps(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def per_field_text(cfg):
    return [dumps(v) for v in cfg]


# _profile() 不产出 max_touch_points / ua_* / is_mobile，Rust 侧用这里的默认值补齐。
PROFILE_DEFAULTS = {
    "max_touch_points": 0,
    "ua_brands": [],
    "ua_platform_version": "",
    "ua_arch": "",
    "ua_bitness": "",
    "is_mobile": False,
}


def profile_dict(p):
    out = {k: p.get(k, PROFILE_DEFAULTS.get(k)) for k in (
        "user_agent", "language", "languages", "timezone_name", "timezone_offset",
        "tz_label", "screen_width", "screen_height", "hardware_concurrency",
        "platform", "vendor", "device_memory", "device_pixel_ratio",
        "max_touch_points", "ua_brands", "ua_platform_version", "ua_arch",
        "ua_bitness", "is_mobile", "page_time_origin_ms",
    )}
    # serde_json 解析 JSON 数字会差 1 ulp，所以浮点同时给出 CPython repr 文本，
    # Rust 侧只用 repr 文本（str::parse 是正确舍入的）做逐位比较。
    out["device_pixel_ratio_repr"] = repr(out["device_pixel_ratio"])
    out["page_time_origin_ms_repr"] = repr(out["page_time_origin_ms"])
    return out


def decode_token(tok, prefix):
    body = tok[len(prefix):]
    assert body.endswith("~S"), tok[-8:]
    return base64.b64decode(body[:-2]).decode("utf-8")


def scenario(rng_kind, profile_kind, fp, opts):
    """每次产物都用全新的 rng 流，互相隔离，便于定位不一致。"""
    out = {"rng": rng_kind, "profile_kind": profile_kind}

    # 1) profile（消耗第 1 个 uniform 抽样）
    install_fakes(make_rng(rng_kind))
    if profile_kind == "fingerprint":
        prof = sp._profile_from_fingerprint(fp)
    else:
        prof = sp._profile(**opts)
    out["profile"] = profile_dict(prof)

    # 2) build_config（profile + 5 次随机抽样）
    install_fakes(make_rng(rng_kind))
    prof = sp._profile_from_fingerprint(fp) if profile_kind == "fingerprint" else sp._profile(**opts)
    cfg = sp.build_config(prof, SID, 0)
    out["config"] = {"json": dumps(cfg), "fields": per_field_text(cfg)}

    # 3) requirements_token（内部再跑一次 build_config + PoW）
    install_fakes(make_rng(rng_kind))
    prof = sp._profile_from_fingerprint(fp) if profile_kind == "fingerprint" else sp._profile(**opts)
    req = sp.requirements_token(prof, SID)
    req_cfg = json.loads(decode_token(req, "gAAAAAC"))
    out["requirements"] = {
        "token": req,
        "embedded_json": decode_token(req, "gAAAAAC"),
        "attempt": req_cfg[3],
        "elapsed_ms": req_cfg[9],
    }

    # 4) enforcement_token（challenge 里的 seed/difficulty 驱动 PoW）
    install_fakes(make_rng(rng_kind))
    prof = sp._profile_from_fingerprint(fp) if profile_kind == "fingerprint" else sp._profile(**opts)
    enf = sp.enforcement_token(CHALLENGE, prof, SID)
    enf_cfg = json.loads(decode_token(enf, "gAAAAAB"))
    out["enforcement"] = {
        "token": enf,
        "embedded_json": decode_token(enf, "gAAAAAB"),
        "attempt": enf_cfg[3],
        "elapsed_ms": enf_cfg[9],
    }
    return out


def fnv_cases():
    samples = [
        "",
        "a",
        "abc",
        "0",
        "gAAAAAC",
        'gAAAAAC[2134,"Tue Oct 27 2026 02:45:46 GMT+0900 (\u65e5\u672c\u6a19\u6e96\u6642)",4294967296]',
        "platform-−Win32",
    ]
    # 覆盖 code point > 0xFFFFFFFF 的补充样本（Python 迭代 code point）
    samples.append("日本標準時シンガポール日本語")
    samples.append("emoji-🙂-𝄞")
    return [{"input": s, "hash": sp._fnv1a(s)} for s in samples]


def float_cases():
    curated = [
        "0.0", "-0.0", "0.5", "0.1", "0.2", "0.30000000000000004",
        "0.3333333333333333", "0.9999999999999999", "1.0", "100.0",
        "1234.5", "123456789.123456789", "0.0001", "0.00001", "1e-05",
        "1e-17", "1e-18", "5e-324", "1e+16", "1e+15",
        "1.7976931348623157e+308", "2.2250738585072014e-308",
        "1e+300", "0.1234567890123456789", "3.141592653589793",
    ]
    rnd = py_random.Random(1234)
    for _ in range(150):
        curated.append(repr(rnd.random()))
    for _ in range(50):
        curated.append(repr(rnd.random() * 10 ** rnd.randint(-6, 6)))

    seen, cases = set(), []
    for raw in curated:
        if raw in seen:
            continue
        seen.add(raw)
        x = float(raw)
        r17 = round(x, 17)
        cases.append({
            "raw": raw,
            "repr_raw": repr(x),
            "round17": repr(r17),
            "json17": dumps(r17),
            "json_raw_rounded": dumps(round(x, 17)),
        })
    return cases


def round_int_cases():
    vals = ["0.0", "0.5", "1.5", "2.5", "-0.5", "-1.5", "24.5", "39.5",
            "0.49999999999999994", "12.4999", "12.5", "40.0", "8.0", "1e-9",
            "1793036745976.0", "3.7", "-3.7", "-2.5"]
    return [{"raw": v, "round": round(float(v)), "json": dumps(round(float(v)))} for v in vals]


def date_cases():
    labels = {
        540: "日本標準時",
        480: "中国标准时间",
        0: "协调世界时",
        -300: "Eastern Standard Time",
        -480: "太平洋标准时间",
        -570: "unknown-zone",
        330: "India Standard Time",
    }
    stamps = [
        1793036746210.0,
        1793036746750.0,          # 亚秒，秒位不变
        1793036400000.0,          # 整点
        1793040000000.0,
        1792992000000.0,          # 2026-10-26T00:00:00Z
        1793037000000.0,
        1793062800000.0,
        1609459199000.0,          # 2020-12-31T23:59:59Z
        0.0,
    ]
    out = []
    for off in sorted(labels):
        for ms in stamps:
            FrozenDatetime.set_ms(ms)
            prof = {"timezone_offset": off, "tz_label": labels[off]}
            out.append({
                "offset_minutes": off,
                "now_ms": ms,
                "now_ms_repr": repr(ms),
                "tz_label": labels[off],
                "out": sp._js_date(prof),
            })
    return out


def main():
    global CHALLENGE, FP
    sample = json.loads((ROOT / "sample_challenge.json").read_text(encoding="utf-8"))
    FP = sample["fp"]
    CHALLENGE = sample["challenge"]

    explicit_opts = {
        "user_agent": "",
        "screen": "1536x864",
        "lang": "zh-CN",
        "languages": "zh-CN,zh;q=0.9,en;q=0.8",
        "platform": "MacIntel",
        "vendor": None,
        "hardware_concurrency": 0,
        "device_memory": 0,
        "timezone": "Asia/Shanghai",
        "device_pixel_ratio": 0.0,
    }

    cases = [
        scenario("const", "fingerprint", FP, explicit_opts),
        scenario("lcg", "fingerprint", FP, explicit_opts),
        scenario("const", "explicit", FP, explicit_opts),
        scenario("lcg", "explicit", FP, explicit_opts),
    ]
    for i, c in enumerate(cases):
        c["name"] = f"case{i}_{c['rng']}_{c['profile_kind']}"

    expected = {
        "meta": {
            "generated_by": "tools/token_parity.py (Python oracle: sentinel_py.py)",
            "oracle": str(ORACLE_DIR / "sentinel_py.py"),
            "sentinel_version": sp.SENTINEL_VERSION,
            "now_ms": NOW_MS,
            "now_ms_repr": repr(NOW_MS),
            "sid": SID,
            "uuid_seed": UUID_SEED,
            "const_value": CONST_VALUE,
            "lcg": {"seed": LCG_SEED, "a": LCG_A, "c": LCG_C, "mod": LCG_MOD},
            "pow": {
                "seed": CHALLENGE["proofofwork"]["seed"],
                "difficulty": CHALLENGE["proofofwork"]["difficulty"],
            },
            "explicit_profile_options": explicit_opts,
        },
        "fp": FP,
        "cases": cases,
        "fnv_cases": fnv_cases(),
        "float_cases": float_cases(),
        "round_int_cases": round_int_cases(),
        "date_cases": date_cases(),
    }

    out_path = ROOT / "tests" / "token_expected.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(expected, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print("wrote", out_path)
    print("cases:", len(cases), "| floats:", len(expected["float_cases"]),
          "| dates:", len(expected["date_cases"]), "| fnv:", len(expected["fnv_cases"]))
    for c in cases:
        print(f"  {c['name']:<22} cfg_len={len(c['config']['json']):<4} "
              f"req_attempt={c['requirements']['attempt']:<4} "
              f"enf_attempt={c['enforcement']['attempt']:<5} "
              f"req_len={len(c['requirements']['token'])} enf_len={len(c['enforcement']['token'])}")


if __name__ == "__main__":
    main()
