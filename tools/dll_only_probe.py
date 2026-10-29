# -*- coding: utf-8 -*-
"""模拟「只拿到一个 DLL」的人：干净目录 + 干净环境，看能用多少。"""
import ctypes
import json
import os
import shutil
import subprocess
import sys
import tempfile

CWD = os.getcwd()
# 路径优先取环境变量，缺省值相对**当前工作目录**（在仓库根目录运行即可）。
SRC = os.environ.get("SRS_DLL") or os.path.join(CWD, "target", "release", "sentinel_rs.dll")
SAMPLE = os.environ.get("SRS_SAMPLE") or os.path.join(CWD, "sample_challenge.json")

CASE = r"""
import ctypes, json, os, sys
dll = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentinel_rs.vmp.dll")
sample = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_challenge.json")
try:
    lib = ctypes.CDLL(dll)
except OSError as e:
    print("LOAD_FAIL:", e); sys.exit(2)
lib.srs_version.restype = ctypes.c_void_p
lib.srs_free.argtypes = [ctypes.c_void_p]
def take(p):
    if not p: return ""
    s = ctypes.string_at(p).decode("utf-8", "replace"); lib.srs_free(p); return s
print("version:", take(lib.srs_version()))

blob = json.load(open(sample, encoding="utf-8"))
lib.srs_mint_t.restype = ctypes.c_void_p
lib.srs_mint_t.argtypes = [ctypes.c_char_p]*3
fp = json.dumps(blob.get("fp") or {}).encode()
t = take(lib.srs_mint_t(blob["challenge"]["turnstile"]["dx"].encode(), blob["p"].encode(), fp))
print("mint_t:", ("OK len=%d" % len(t)) if not t.startswith("ERR") else t[:120])

lib.srs_register.restype = ctypes.c_void_p
lib.srs_register.argtypes = [ctypes.c_char_p]
dry = take(lib.srs_register(json.dumps({"SENTINEL_PROXY": "", "SENTINEL_COUNT": "1"}).encode()))
print("register(dry):", dry[:160])

live = take(lib.srs_register(json.dumps({
    "SENTINEL_PROXY": "", "SENTINEL_COUNT": "1", "SENTINEL_LIVE_REGISTER": "1"
}).encode()))
print("register(live):", live[:200])
"""


def main():
    tmp = tempfile.mkdtemp(prefix="dllonly_")
    shutil.copy2(SRC, os.path.join(tmp, "sentinel_rs.vmp.dll"))
    shutil.copy2(SAMPLE, os.path.join(tmp, "sample_challenge.json"))
    script = os.path.join(tmp, "probe.py")
    open(script, "w", encoding="utf-8").write(CASE)

    fake_home = os.path.join(tmp, "home")
    os.makedirs(fake_home, exist_ok=True)

    env = {k: v for k, v in os.environ.items()
           if not k.upper().startswith(("REG_MAIL", "SENTINEL", "OTP_", "TURB_", "OPENAI"))}
    env["HOME"] = fake_home
    env["USERPROFILE"] = fake_home
    env["PYTHONIOENCODING"] = "utf-8"
    env.pop("PROTOCOL_PROXY_POOL", None)

    print(f"实验目录: {tmp}")
    print(f"假 HOME : {fake_home}（无任何邮箱凭据文件）")
    print("-" * 60)
    proc = subprocess.run([sys.executable, script], cwd=tmp, env=env,
                          capture_output=True, text=True, encoding="utf-8", errors="replace")
    print(proc.stdout.strip())
    if proc.returncode:
        print("exit:", proc.returncode)
        print(proc.stderr.strip()[-500:])


if __name__ == "__main__":
    main()
