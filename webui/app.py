#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sentinel-rs 本地 WebUI（单文件 / 纯标准库 / 完全离线）。

用途
----
给 `sentinel-rs register` 套一层本地网页：
  * 配置面板（数量 / 并发 / 邮箱清单 / 代理模式 / 2FA / OTP 参数），
    存 `webui/webui_config.json`，重启保留；
  * 实时进度：子进程 stdout+stderr 收进内存环形缓冲（最近 2000 行），
    前端 1 秒轮询增量拉取，解析 `[n/total] OK|FAIL` 统计成败；
  * 账号列表：只读 `data/sentinel-rs.db` 的 `accounts` 表；
  * 查活：对每个有 access_token 的账号跑一次 chatgpt.com/backend-api/me。

启动
----
    python webui\\app.py                 # 默认 127.0.0.1:8787，自动开浏览器
    python webui\\app.py --port 9000
    python webui\\app.py --no-browser    # 不自动开浏览器

约束（刻意的）
--------------
* 只监听 127.0.0.1；非回环地址需要额外 --allow-remote（默认拒绝）。
* 不写死任何凭据：邮箱 / 代理 / token 都来自外部文件或数据库，本文件只有路径默认值。
* 只读数据库（sqlite `mode=ro`），写库仍然由 Rust 侧负责。
* 子进程环境变量单独构造，不修改父进程 os.environ。
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# ───────────────────────────── 路径 ─────────────────────────────

APP_DIR = Path(__file__).resolve().parent
REPO_ROOT = APP_DIR.parent
CONFIG_PATH = APP_DIR / "webui_config.json"
EXE_RELEASE = REPO_ROOT / "target" / "release" / "sentinel-rs.exe"
EXE_DEBUG = REPO_ROOT / "target" / "debug" / "sentinel-rs.exe"
DB_DEFAULT = REPO_ROOT / "data" / "sentinel-rs.db"

LOG_CAPACITY = 2000
BODY_LIMIT = 1 << 20  # 1 MiB

CHECK_URL = "https://chatgpt.com/backend-api/me"
DEFAULT_SOCKS = "127.0.0.1:10808"

# ───────────────────────────── 配置 ─────────────────────────────

DEFAULT_CONFIG = {
    "count": 1,
    "concurrency": 1,
    # 留空：由用户在界面里填。不预置任何个人路径 / 清单文件名。
    "email_file": "",
    "proxy_mode": "none",          # none | single | file
    "proxy": "",
    "proxy_file": "",
    "mail_allow_insecure": False,  # REG_MAIL_ALLOW_INSECURE=1
    "enable_2fa": False,           # SENTINEL_ENABLE_2FA
    "otp_max_wait": 600,           # OTP_MAX_WAIT
    "otp_poll_interval": 3,        # OTP_POLL_INTERVAL
    "live": False,                 # True 才会注入 SENTINEL_LIVE_REGISTER=1
    "log_level": "info",           # SENTINEL_LOG
    "exe": "",                     # 留空 = 自动找 target/release|debug
    "db_path": "",                 # 留空 = data/sentinel-rs.db
    "check_socks5": DEFAULT_SOCKS,  # 查活走的 socks5-hostname
    "check_timeout": 20,           # 查活单次 curl 超时（秒）
}

PROXY_MODES = ("none", "single", "file")
LOG_LEVELS = ("trace", "debug", "info", "warn", "error", "off")


def _as_int(value, default: int, low: int | None = None, high: int | None = None) -> int:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    if low is not None and number < low:
        number = low
    if high is not None and number > high:
        number = high
    return number


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on", "y")


def _as_str(value, default: str = "") -> str:
    if value is None:
        return default
    return str(value).strip()


def normalize_config(raw: dict | None) -> dict:
    """把任意输入钳成规整的配置（未知键丢弃，缺失键取默认）。"""
    raw = raw if isinstance(raw, dict) else {}
    base = dict(DEFAULT_CONFIG)
    for key, value in raw.items():
        if key not in base:
            continue
        base[key] = value

    cfg = dict(base)
    cfg["count"] = _as_int(base["count"], DEFAULT_CONFIG["count"], 1, 100000)
    cfg["concurrency"] = _as_int(base["concurrency"], DEFAULT_CONFIG["concurrency"], 1, 256)
    cfg["email_file"] = _as_str(base["email_file"])
    mode = _as_str(base["proxy_mode"]).lower()
    cfg["proxy_mode"] = mode if mode in PROXY_MODES else "none"
    cfg["proxy"] = _as_str(base["proxy"])
    cfg["proxy_file"] = _as_str(base["proxy_file"])
    cfg["mail_allow_insecure"] = _as_bool(base["mail_allow_insecure"])
    cfg["enable_2fa"] = _as_bool(base["enable_2fa"])
    cfg["otp_max_wait"] = _as_int(base["otp_max_wait"], DEFAULT_CONFIG["otp_max_wait"], 1, 86400)
    cfg["otp_poll_interval"] = _as_int(
        base["otp_poll_interval"], DEFAULT_CONFIG["otp_poll_interval"], 1, 600
    )
    cfg["live"] = _as_bool(base["live"])
    level = _as_str(base["log_level"]).lower()
    cfg["log_level"] = level if level in LOG_LEVELS else "info"
    cfg["exe"] = _as_str(base["exe"])
    cfg["db_path"] = _as_str(base["db_path"])
    cfg["check_socks5"] = _as_str(base["check_socks5"]) or DEFAULT_SOCKS
    cfg["check_timeout"] = _as_int(base["check_timeout"], DEFAULT_CONFIG["check_timeout"], 3, 300)
    return cfg


_config_lock = threading.Lock()


def load_config() -> dict:
    with _config_lock:
        if CONFIG_PATH.is_file():
            try:
                raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                raw = {}
        else:
            raw = {}
        return normalize_config(raw)


def merge_config(body: dict | None) -> dict:
    """把传入的（可能是 UI 的全量表单）合并到**当前已保存**的配置上，再规整。

    这样手改过 `webui_config.json` 里的 `exe` / `db_path` / `check_socks5` 等
    UI 表单里没有的字段，不会被一次「保存配置」悄悄打回默认值。
    """
    current = load_config()
    for key, value in (body or {}).items():
        if key in DEFAULT_CONFIG:
            current[key] = value
    return normalize_config(current)


def save_config(cfg: dict) -> dict:
    cfg = normalize_config(cfg)
    with _config_lock:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        tmp = CONFIG_PATH.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, CONFIG_PATH)
    return cfg


# ───────────────────────────── 路径解析 ─────────────────────────────

def resolve_exe(cfg: dict) -> tuple[Path | None, str]:
    """返回 (可执行文件, 错误信息)。"""
    explicit = cfg.get("exe", "").strip()
    if explicit:
        path = Path(explicit).expanduser()
        if path.is_file():
            return path, ""
        return None, f"配置里指定的可执行文件不存在: {path}"
    for candidate in (EXE_RELEASE, EXE_DEBUG):
        if candidate.is_file():
            return candidate, ""
    return None, (
        "找不到 sentinel-rs 可执行文件，试过:\n"
        f"  - {EXE_RELEASE}\n  - {EXE_DEBUG}\n"
        "请先在仓库根运行 build.ps1 或 cargo build --release。"
    )


def resolve_db(cfg: dict) -> Path:
    raw = cfg.get("db_path", "").strip()
    if raw:
        path = Path(raw).expanduser()
        return path if path.is_absolute() else (REPO_ROOT / path)
    return DB_DEFAULT


STRIP_ENV = (
    "SENTINEL_COUNT", "REGISTER_COUNT", "SENTINEL_DB_PATH",
    "SENTINEL_PROXY", "SENTINEL_PROXY_FILE",
    "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY",
    "https_proxy", "http_proxy", "all_proxy",
    "REG_MAIL_EMAIL_FILE", "SENTINEL_ENABLE_2FA",
    "OTP_MAX_WAIT", "OTP_POLL_INTERVAL",
    "SENTINEL_LIVE_REGISTER", "REG_MAIL_ALLOW_INSECURE",
)

PROXY_CRED_RE = re.compile(r"(://[^/@\s:]+):[^/@\s]+@")


def mask_proxy(value: str) -> str:
    """把 `scheme://user:pass@host` 里的口令打成 ***（只用于显示）。"""
    return PROXY_CRED_RE.sub(r"\1:***@", value)


def build_invocation(cfg: dict) -> tuple[list[str], dict, str]:
    """构造子进程 argv / env。返回 (argv, env, 错误)。env 是全新 dict，不动父进程。"""
    exe, err = resolve_exe(cfg)
    if exe is None:
        return [], {}, err

    db = resolve_db(cfg)
    argv = [
        str(exe), "register",
        "-n", str(cfg["count"]),
        "-c", str(cfg["concurrency"]),
        "--db", str(db),
    ]

    email_file = cfg["email_file"]
    if email_file:
        argv += ["--email-file", email_file]

    mode = cfg["proxy_mode"]
    # 单代理刻意只用环境变量注入：`--proxy` 会把口令暴露在进程命令行里
    # （任务管理器 / Process Explorer / 我们自己的 `$ cmd` 回显都能看到）。
    # SENTINEL_PROXY 与 --proxy 走同一条解析路径，行为一致。
    if mode == "file" and cfg["proxy_file"]:
        argv += ["--proxy-file", cfg["proxy_file"]]

    if cfg["enable_2fa"]:
        argv.append("--2fa")
    argv.append("--live" if cfg["live"] else "--dry-run")

    env = {k: v for k, v in os.environ.items() if k not in STRIP_ENV}
    env["SENTINEL_REPO_ROOT"] = str(REPO_ROOT)
    env["SENTINEL_LOG"] = cfg["log_level"]
    env["SENTINEL_COUNT"] = str(cfg["count"])
    env["SENTINEL_DB_PATH"] = str(db)
    env["OTP_MAX_WAIT"] = str(cfg["otp_max_wait"])
    env["OTP_POLL_INTERVAL"] = str(cfg["otp_poll_interval"])
    env["RUST_BACKTRACE"] = "1"
    if cfg["mail_allow_insecure"]:
        env["REG_MAIL_ALLOW_INSECURE"] = "1"
    if cfg["enable_2fa"]:
        env["SENTINEL_ENABLE_2FA"] = "1"
    if cfg["live"]:
        env["SENTINEL_LIVE_REGISTER"] = "1"
    if mode == "single" and cfg["proxy"]:
        env["SENTINEL_PROXY"] = cfg["proxy"]
    elif mode == "file" and cfg["proxy_file"]:
        env["SENTINEL_PROXY_FILE"] = cfg["proxy_file"]
    if email_file:
        env["REG_MAIL_EMAIL_FILE"] = email_file
    return argv, env, ""


def validate_for_start(cfg: dict) -> str:
    """启动前校验。返回错误文本，空串表示可以启动。"""
    exe, err = resolve_exe(cfg)
    if exe is None:
        return err

    if cfg["count"] < 1:
        return "-n（数量）必须 >= 1"
    if cfg["concurrency"] < 1:
        return "-c（并发）必须 >= 1"

    email_file = cfg["email_file"]
    if not email_file:
        if cfg["live"]:
            return "LIVE 模式必须指定邮箱清单（--email-file）"
    elif not Path(email_file).expanduser().is_file():
        return f"邮箱清单不存在: {email_file}"

    mode = cfg["proxy_mode"]
    if mode == "single":
        if not cfg["proxy"]:
            return "已选择「单个代理」模式，但代理地址为空"
        value = cfg["proxy"]
        if "://" in value:
            parsed = urllib.parse.urlparse(value)
            if not parsed.hostname:
                return f"代理地址无法解析: {value}"
        elif ":" not in value:
            return f"代理地址需要 host:port 形式: {value}"
    elif mode == "file":
        if not cfg["proxy_file"]:
            return "已选择「代理清单」模式，但清单路径为空"
        if not Path(cfg["proxy_file"]).expanduser().is_file():
            return f"代理清单不存在: {cfg['proxy_file']}"

    db = resolve_db(cfg)
    db_parent = db.parent
    if not db_parent.is_dir() and cfg["live"]:
        return f"数据库目录不存在: {db_parent}"

    return ""


# ───────────────────────────── 日志环形缓冲 ─────────────────────────────

class LogRing:
    """线程安全的有界日志缓冲；每行带单调递增的绝对序号，供前端增量拉取。"""

    def __init__(self, capacity: int = LOG_CAPACITY):
        self._cap = capacity
        self._items: collections.deque[tuple[int, str]] = collections.deque()
        self._next = 0
        self._lock = threading.Lock()

    def clear(self) -> None:
        with self._lock:
            self._items.clear()
            self._next = 0

    def append(self, line: str) -> None:
        with self._lock:
            self._items.append((self._next, line))
            self._next += 1
            while len(self._items) > self._cap:
                self._items.popleft()

    def since(self, offset: int) -> tuple[list[str], int, int]:
        """返回 (offset 之后的行, 下一个 offset, 因越界被丢弃的行数)。"""
        with self._lock:
            if not self._items:
                return [], self._next, 0
            first = self._items[0][0]
            dropped = 0
            if offset < first:
                dropped = first - offset
                offset = first
            lines = [text for index, text in self._items if index >= offset]
            return lines, self._next, dropped


# ───────────────────────────── 日志解析（成败计数） ─────────────────────────────

RE_TOTAL = re.compile(r"^数量\s*:\s*(\d+)")
RE_PROGRESS_OK = re.compile(r"^\[(\d+)/(\d+)\]\s+OK\s+(\S+)")
RE_PROGRESS_FAIL = re.compile(r"^\[(\d+)/(\d+)\]\s+(?:FAIL|JOIN-ERR)\b")
RE_SEQ_DRYRUN_OK = re.compile(r"^占位身份:\s+(\S+)")
RE_SEQ_LIVE_OK = re.compile(r"^注册完成:\s+(\S+)")
RE_SEQ_FAIL = re.compile(r"^本次失败:")


# ───────────────────────────── 注册进程管理 ─────────────────────────────

class Runner:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.logs = LogRing(LOG_CAPACITY)
        self._proc: subprocess.Popen | None = None
        self._pid: int | None = None
        self._running = False
        self._started = 0.0
        self._elapsed = 0.0
        self._ok = 0
        self._fail = 0
        self._total = 0
        self._concurrency = 1
        self._mode = "dry-run"
        self._exit_code: int | None = None
        self._stop_requested = False
        self._started_at = 0.0

    # ── 内部工具 ──────────────────────────────────────────
    def _reset_locked(self, cfg: dict) -> None:
        self.logs.clear()
        self._ok = 0
        self._fail = 0
        self._total = cfg["count"]
        self._concurrency = cfg["concurrency"]
        self._mode = "LIVE" if cfg["live"] else "dry-run"
        self._exit_code = None
        self._stop_requested = False
        self._elapsed = 0.0

    def _parse_line_locked(self, line: str) -> None:
        match = RE_TOTAL.match(line)
        if match:
            self._total = int(match.group(1))
            return
        match = RE_PROGRESS_OK.match(line)
        if match:
            self._ok += 1
            self._total = max(self._total, int(match.group(2)))
            return
        match = RE_PROGRESS_FAIL.match(line)
        if match:
            self._fail += 1
            self._total = max(self._total, int(match.group(2)))
            return
        if RE_SEQ_DRYRUN_OK.match(line) or RE_SEQ_LIVE_OK.match(line):
            self._ok += 1
            return
        if RE_SEQ_FAIL.match(line):
            self._fail += 1

    def emit_raw(self, text: str) -> None:
        """外部注入一行日志（带脱敏）。"""
        lines = text.splitlines() or [""]
        with self._lock:
            for line in lines:
                line = PROXY_CRED_RE.sub(r"\1:***@", line.rstrip("\r\n"))
                self._parse_line_locked(line)
                self.logs.append(line)

    # ── 启动 / 停止 ──────────────────────────────────────
    def start(self, cfg: dict) -> tuple[bool, dict]:
        error = validate_for_start(cfg)
        if error:
            return False, {"ok": False, "error": error}

        with self._lock:
            if self._running:
                return False, {
                    "ok": False,
                    "error": f"已有注册进程在运行（pid={self._pid}），请先点「停止」",
                }
            argv, env, error = build_invocation(cfg)
            if error:
                return False, {"ok": False, "error": error}

            self._reset_locked(cfg)
            self.emit_raw("$ " + " ".join(mask_proxy(part) for part in argv))
            self.emit_raw(
                "== WebUI 启动：数量 {n} / 并发 {c} / 模式 {m} / 2FA {f} / "
                "明文 http 放行 {i} / OTP {w}s@{p}s ==".format(
                    n=cfg["count"], c=cfg["concurrency"], m=self._mode,
                    f="开" if cfg["enable_2fa"] else "关",
                    i="是" if cfg["mail_allow_insecure"] else "否",
                    w=cfg["otp_max_wait"], p=cfg["otp_poll_interval"],
                )
            )

            flags = 0
            if os.name == "nt":
                flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            try:
                proc = subprocess.Popen(
                    argv,
                    cwd=str(REPO_ROOT),
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    bufsize=0,
                    creationflags=flags,
                )
            except OSError as exc:
                self._running = False
                self.emit_raw(f"启动失败: {exc}")
                return False, {"ok": False, "error": f"启动失败: {exc}"}

            self._proc = proc
            self._pid = proc.pid
            self._running = True
            self._started = time.monotonic()
            self._started_at = time.time()
            threading.Thread(target=self._read_loop, args=(proc,), daemon=True).start()
            return True, {"ok": True, "pid": proc.pid}

    def _read_loop(self, proc: subprocess.Popen) -> None:
        buffer = b""
        try:
            while True:
                chunk = proc.stdout.read(8192) if proc.stdout else b""
                if not chunk:
                    break
                buffer += chunk
                while True:
                    index = buffer.find(b"\n")
                    if index < 0:
                        break
                    raw, buffer = buffer[:index], buffer[index + 1:]
                    self.emit_raw(raw.decode("utf-8", "replace"))
            if buffer:
                self.emit_raw(buffer.decode("utf-8", "replace"))
        except (OSError, ValueError):
            pass
        finally:
            try:
                code = proc.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover
                code = -1
            with self._lock:
                self._elapsed = time.monotonic() - self._started if self._started else 0.0
                self._running = False
                self._exit_code = code
                stopped = self._stop_requested
            self.emit_raw(
                f"== 进程退出 exit={code}（{'已停止' if stopped else '结束'}）"
                f" 成功 {self._ok} / 失败 {self._fail} =="
            )

    def stop(self) -> tuple[bool, dict]:
        with self._lock:
            if not self._running or self._proc is None:
                return False, {"ok": False, "error": "当前没有正在运行的注册进程"}
            proc, pid = self._proc, self._pid
            self._stop_requested = True
        self.emit_raw(f"== 收到停止请求：终止进程树 pid={pid} ==")

        try:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/PID", str(pid), "/T", "/F"],
                    capture_output=True, timeout=20,
                )
            else:
                proc.terminate()
        except (OSError, subprocess.SubprocessError) as exc:
            self.emit_raw(f"taskkill 失败: {exc}（回退 proc.kill()）")
            try:
                proc.kill()
            except OSError:
                pass

        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover
            try:
                proc.kill()
            except OSError:
                pass
        return True, {"ok": True, "pid": pid}

    # ── 快照 ─────────────────────────────────────────────
    def status(self) -> dict:
        with self._lock:
            if self._running and self._started:
                elapsed = time.monotonic() - self._started
            else:
                elapsed = self._elapsed
            return {
                "running": self._running,
                "pid": self._pid if self._running else None,
                "elapsed": round(elapsed, 1),
                "ok": self._ok,
                "fail": self._fail,
                "total": self._total,
                "concurrency": self._concurrency,
                "mode": self._mode,
                "exit_code": self._exit_code,
                "started_at": self._started_at,
            }

    def log_page(self, offset: int) -> dict:
        lines, next_offset, dropped = self.logs.since(offset)
        return {
            "lines": lines,
            "next": next_offset,
            "dropped": dropped,
            "running": self._running,
        }


RUNNER = Runner()


# ───────────────────────────── 账号库（只读） ─────────────────────────────

def _db_uri(path: Path) -> str:
    return "file:" + urllib.parse.quote(str(path).replace("\\", "/")) + "?mode=ro"


def fetch_accounts(db_path: Path) -> list | dict:
    if not db_path.is_file():
        return {"ok": False, "error": f"数据库不存在: {db_path}"}
    try:
        conn = sqlite3.connect(_db_uri(db_path), uri=True, timeout=5)
    except sqlite3.Error as exc:
        return {"ok": False, "error": f"打开数据库失败: {exc}"}
    try:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, email, status, access_token, created_at, updated_at "
            "FROM accounts ORDER BY id"
        ).fetchall()
    except sqlite3.Error as exc:
        conn.close()
        return {"ok": False, "error": f"读取 accounts 表失败: {exc}"}
    conn.close()

    accounts = []
    for row in rows:
        token = (row["access_token"] or "").strip()
        accounts.append({
            "id": row["id"],
            "email": row["email"],
            "status": row["status"],
            "has_at": bool(token),
            "created_at": int(row["created_at"] or 0),
            "updated_at": int(row["updated_at"] or 0),
        })
    return accounts


# ───────────────────────────── 查活 ─────────────────────────────

def find_curl() -> str | None:
    for name in ("curl.exe", "curl"):
        found = shutil.which(name)
        if found:
            return found
    fallback = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "curl.exe"
    if fallback.is_file():
        return str(fallback)
    return None


def check_alive(cfg: dict) -> dict:
    """逐个对有 AT 的账号打 chatgpt.com/backend-api/me，返回 {email: status}。"""
    curl = find_curl()
    if not curl:
        return {"_error": "找不到 curl.exe（Windows 10+ 自带；请确认在 PATH 或 C:\\Windows\\System32）"}
    db_path = resolve_db(cfg)
    rows = fetch_accounts(db_path)
    if isinstance(rows, dict):
        return {"_error": rows.get("error", "读取账号失败")}

    socks = cfg["check_socks5"]
    timeout = cfg["check_timeout"]
    results: dict[str, str] = {}
    with_token = 0
    for account in rows:
        if not account["has_at"]:
            continue
        with_token += 1
        status = _curl_check_one(curl, socks, timeout, account["email"], db_path)
        results[account["email"]] = status
        # 逐条写日志，前端可在日志区看到进度
        RUNNER.emit_raw(f"[查活] {account['email']} → {status}")
    results["_curl"] = curl
    results["_socks5"] = socks
    results["_targets"] = str(with_token)
    RUNNER.emit_raw(f"== 查活结束：{with_token} 个有 AT 的账号 ==")
    return results


def _token_for(db_path: Path, email: str) -> str:
    conn = sqlite3.connect(_db_uri(db_path), uri=True, timeout=5)
    try:
        row = conn.execute(
            "SELECT access_token FROM accounts WHERE email = ?", (email,)
        ).fetchone()
    finally:
        conn.close()
    return (row[0] or "").strip() if row else ""


def _curl_check_one(curl: str, socks: str, timeout: int, email: str, db_path: Path) -> str:
    try:
        token = _token_for(db_path, email)
    except sqlite3.Error as exc:
        return f"错误(db:{exc})"
    if not token:
        return "无AT"

    argv = [
        curl, "-s", "-o", "NUL" if os.name == "nt" else "/dev/null",
        "-w", "%{http_code}",
        "--socks5-hostname", socks,
        "-H", "authorization: Bearer " + token,
        "--max-time", str(timeout),
        CHECK_URL,
    ]
    try:
        proc = subprocess.run(
            argv, capture_output=True, timeout=timeout + 10,
            stdin=subprocess.DEVNULL, shell=False,
        )
    except subprocess.TimeoutExpired:
        return "超时"
    except OSError as exc:
        return f"错误({exc})"

    code = proc.stdout.decode("utf-8", "replace").strip()
    if proc.returncode == 0 and re.fullmatch(r"\d{3}", code):
        return code
    if code and re.fullmatch(r"\d{3}", code) and code != "000":
        return code
    detail = proc.stderr.decode("utf-8", "replace").strip().splitlines()
    hint = detail[-1][:80] if detail else ""
    return f"错误(rc={proc.returncode}{(' ' + hint) if hint else ''})"


# ───────────────────────────── 页面 ─────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>sentinel-rs 注册控制台</title>
<style>
:root{
  --bg:#0e1014; --panel:#161a22; --panel2:#1c2230; --bd:#2a3140;
  --fg:#e7eaf0; --muted:#8c95a8; --acc:#4c8dff; --acc2:#2f6fe0;
  --ok:#3fbf7f; --bad:#ff6b6b; --warn:#ffcf5c;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0;background:var(--bg);color:var(--fg);
  font-family:-apple-system,"Segoe UI","Microsoft YaHei",system-ui,sans-serif;
  font-size:14px;line-height:1.5}
h1{font-size:18px;margin:0;letter-spacing:.5px}
h2{font-size:13px;margin:0 0 10px;color:var(--muted);font-weight:600;
  letter-spacing:1px;text-transform:uppercase}
a{color:var(--acc)}
header{position:sticky;top:0;z-index:20;background:linear-gradient(180deg,#12151c,#0e1014);
  border-bottom:1px solid var(--bd);padding:12px 16px 10px}
.hrow{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.logo{width:10px;height:10px;border-radius:50%;background:var(--acc);
  box-shadow:0 0 10px var(--acc)}
.badges{display:flex;gap:8px;flex-wrap:wrap;margin-left:auto}
.badge{display:flex;flex-direction:column;min-width:74px;padding:5px 10px;
  background:var(--panel);border:1px solid var(--bd);border-radius:8px}
.badge .k{font-size:11px;color:var(--muted)}
.badge .v{font-size:15px;font-weight:600;font-variant-numeric:tabular-nums}
.v.ok{color:var(--ok)} .v.bad{color:var(--bad)} .v.acc{color:var(--acc)}
main{padding:14px 16px 40px;display:grid;gap:14px;min-width:0;
  grid-template-columns:minmax(330px,430px) minmax(0,1fr)}
.panel{background:var(--panel);border:1px solid var(--bd);border-radius:12px;padding:14px;
  min-width:0}
.panel.span{grid-column:1/-1}
label.field{display:block;margin-bottom:10px;min-width:0}
label.field > span{display:block;font-size:12px;color:var(--muted);margin-bottom:4px;
  overflow-wrap:anywhere}
input[type=text],input[type=number],select{width:100%;min-width:0;padding:7px 9px;
  border-radius:8px;background:var(--panel2);color:var(--fg);border:1px solid var(--bd);
  font-family:inherit;font-size:13px}
input[type=text]:focus,input[type=number]:focus,select:focus{
  outline:none;border-color:var(--acc)}
input[type=text]{font-family:ui-monospace,Consolas,"Courier New",monospace;font-size:12px}
.two{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.two > *{min-width:0}
.radios{display:flex;flex-direction:column;gap:6px;margin:2px 0 10px}
.radios label{display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer}
.checks{display:flex;flex-direction:column;gap:8px;margin:4px 0 12px}
.checks label{display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer}
input[type=checkbox],input[type=radio]{accent-color:var(--acc);width:15px;height:15px}
.btns{display:flex;gap:8px;flex-wrap:wrap}
button{font-family:inherit;font-size:13px;padding:8px 14px;border-radius:8px;
  border:1px solid var(--bd);background:var(--panel2);color:var(--fg);cursor:pointer}
button:hover:not(:disabled){border-color:var(--acc);color:#fff}
button:disabled{opacity:.45;cursor:not-allowed}
button.primary{background:var(--acc);border-color:var(--acc);color:#08111f;font-weight:600}
button.primary:hover:not(:disabled){background:#6ba0ff}
button.danger{background:#3a1d22;border-color:#5b2b33;color:#ffb3b3}
button.danger:hover:not(:disabled){background:#571f28;color:#fff}
.hint{font-size:11.5px;color:var(--muted);margin-top:8px;line-height:1.6}
.banner{display:none;margin:0 0 12px;padding:9px 12px;border-radius:8px;font-size:13px;
  border:1px solid #5b2b33;background:#2a1a1e;color:#ffb3b3;white-space:pre-wrap}
.banner.show{display:block}
.banner.info{border-color:#2b4a5b;background:#16222a;color:#a8d8ee}
.logbox{height:420px;overflow:auto;background:#0a0c10;border:1px solid var(--bd);
  border-radius:10px;padding:10px 12px;
  font-family:ui-monospace,Consolas,"Courier New",monospace;font-size:12px;
  line-height:1.45;white-space:pre-wrap;word-break:break-all}
.logbox .ln{color:#c9d1de}
.logbox .ln.ok{color:var(--ok)}
.logbox .ln.bad{color:var(--bad)}
.logbox .ln.warn{color:var(--warn)}
.logbox .ln.sys{color:var(--acc)}
.logbox .ln.mut{color:#5f6980}
.statline{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--muted);
  margin-bottom:10px}
.statline b{color:var(--fg);font-variant-numeric:tabular-nums}
.tablewrap{overflow:auto;border:1px solid var(--bd);border-radius:10px;max-height:460px}
table{border-collapse:collapse;width:100%;font-size:12.5px}
th,td{padding:7px 10px;text-align:left;border-bottom:1px solid #222a36;
  white-space:nowrap}
th{position:sticky;top:0;background:var(--panel2);color:var(--muted);font-weight:600;
  z-index:1}
tbody tr:hover{background:#1a2130}
td.mono{font-family:ui-monospace,Consolas,monospace}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:11.5px;
  border:1px solid var(--bd);background:#20293a}
.pill.registered{color:var(--ok);border-color:#2b5b43;background:#15261d}
.pill.pending_otp{color:var(--warn);border-color:#5b4c2b;background:#262013}
.pill.other{color:var(--muted)}
.at-yes{color:var(--ok)} .at-no{color:#5f6980}
.chk{font-family:ui-monospace,Consolas,monospace}
.chk.s200{color:var(--ok)} .chk.s-bad{color:var(--bad)} .chk.s-odd{color:var(--warn)}
.empty{color:var(--muted);padding:14px;font-size:12.5px}
@media (max-width:900px){
  main{grid-template-columns:minmax(0,1fr);padding:10px 10px 40px}
  .panel.span{grid-column:auto}
  .logbox{height:300px}
  .badges{margin-left:0;width:100%}
  .badge{flex:1 1 30%;min-width:0}
}
@media (max-width:520px){
  header{padding:10px 12px}
  h1{font-size:16px}
  .badge{padding:4px 8px;min-width:0}
  .badge .v{font-size:14px}
  .btns button{flex:1 1 auto}
  .radios label,.checks label{font-size:12.5px}
}
</style>
</head>
<body>
<header>
  <div class="hrow">
    <span class="logo"></span>
    <h1>sentinel-rs 注册控制台</h1>
    <div class="badges">
      <div class="badge"><span class="k">状态</span><span class="v" id="st-state">已停止</span></div>
      <div class="badge"><span class="k">成功</span><span class="v ok" id="st-ok">0</span></div>
      <div class="badge"><span class="k">失败</span><span class="v bad" id="st-fail">0</span></div>
      <div class="badge"><span class="k">已跑时长</span><span class="v" id="st-elapsed">0s</span></div>
      <div class="badge"><span class="k">当前并发</span><span class="v acc" id="st-conc">-</span></div>
      <div class="badge"><span class="k">总数</span><span class="v" id="st-total">-</span></div>
    </div>
  </div>
</header>

<main>
  <section class="panel">
    <h2>配置</h2>
    <div class="banner" id="banner"></div>
    <div class="two">
      <label class="field"><span>数量 -n</span>
        <input type="number" id="cfg-count" min="1" step="1"></label>
      <label class="field"><span>并发 -c</span>
        <input type="number" id="cfg-concurrency" min="1" step="1"></label>
    </div>
    <label class="field"><span>邮箱清单路径 --email-file</span>
      <input type="text" id="cfg-email-file" spellcheck="false"></label>

    <div class="radios" id="proxy-radios">
      <label><input type="radio" name="proxymode" value="none"> 不用代理（直连）</label>
      <label><input type="radio" name="proxymode" value="single"> 单个代理 --proxy</label>
      <label><input type="radio" name="proxymode" value="file"> 代理清单 --proxy-file</label>
    </div>
    <label class="field" id="wrap-proxy"><span>代理地址（host:port 或 scheme://user:pass@host:port）</span>
      <input type="text" id="cfg-proxy" spellcheck="false" placeholder="socks5h://127.0.0.1:1080"></label>
    <label class="field" id="wrap-proxy-file"><span>代理清单路径（每行 host:port:user:pass）</span>
      <input type="text" id="cfg-proxy-file" spellcheck="false"></label>

    <div class="two">
      <label class="field"><span>OTP_MAX_WAIT（秒）</span>
        <input type="number" id="cfg-otp-wait" min="1" step="1"></label>
      <label class="field"><span>OTP_POLL_INTERVAL（秒）</span>
        <input type="number" id="cfg-otp-poll" min="1" step="1"></label>
    </div>

    <div class="checks">
      <label><input type="checkbox" id="cfg-insecure"> REG_MAIL_ALLOW_INSECURE=1（放行明文 http 取码地址）</label>
      <label><input type="checkbox" id="cfg-2fa"> SENTINEL_ENABLE_2FA（注册后绑 TOTP）</label>
      <label><input type="checkbox" id="cfg-live"> SENTINEL_LIVE_REGISTER=1（真实联网注册，会消耗邮箱）</label>
    </div>

    <div class="btns">
      <button id="btn-save">保存配置</button>
      <button class="primary" id="btn-start">开始注册</button>
      <button class="danger" id="btn-stop">停止</button>
    </div>
    <div class="hint">
      默认 dry-run（不联网、不消耗邮箱）。勾选 LIVE 且点「开始注册」才会真实建号。<br>
      配置写入 <code>webui/webui_config.json</code>，重启后自动读回。
    </div>
  </section>

  <section class="panel">
    <h2>实时日志（stdout + stderr）</h2>
    <div class="statline">
      <span>进程 pid：<b id="st-pid">-</b></span>
      <span>模式：<b id="st-mode">-</b></span>
      <span>退出码：<b id="st-exit">-</b></span>
      <span>日志行：<b id="st-lines">0</b></span>
    </div>
    <div class="logbox" id="logbox"><div class="ln mut">（还没有日志。点「开始注册」后这里会实时滚动。）</div></div>
  </section>

  <section class="panel span">
    <h2>账号列表（data/sentinel-rs.db · accounts）</h2>
    <div class="statline">
      <span>总数：<b id="acc-total">-</b></span>
      <span>registered：<b id="acc-registered">-</b></span>
      <span>pending_otp：<b id="acc-pending">-</b></span>
      <span>有 AT：<b id="acc-withat">-</b></span>
      <span id="acc-note"></span>
    </div>
    <div class="btns" style="margin-bottom:10px">
      <button id="btn-refresh">刷新</button>
      <button id="btn-check">查活（有 AT 的账号）</button>
    </div>
    <div class="tablewrap">
      <table>
        <thead><tr>
          <th>id</th><th>email</th><th>status</th><th>AT</th><th>创建时间</th><th>查活</th>
        </tr></thead>
        <tbody id="acc-body">
          <tr><td colspan="6" class="empty">点「刷新」加载账号。</td></tr>
        </tbody>
      </table>
    </div>
  </section>
</main>

<script>
"use strict";
const $ = (id) => document.getElementById(id);
let logOffset = 0;
let logPollTimer = null;
let lastRunning = null;
let checkBusy = false;

function fmtElapsed(sec) {
  sec = Math.max(0, Math.floor(sec || 0));
  const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
  if (h > 0) return h + "h" + String(m).padStart(2, "0") + "m" + String(s).padStart(2, "0") + "s";
  if (m > 0) return m + "m" + String(s).padStart(2, "0") + "s";
  return s + "s";
}

function fmtTime(ts) {
  if (!ts) return "—";
  try {
    const d = new Date(ts * 1000);
    if (isNaN(d.getTime())) return "—";
    const p = (n) => String(n).padStart(2, "0");
    return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) + " " +
           p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
  } catch (e) { return "—"; }
}

async function api(path, options) {
  const resp = await fetch(path, options);
  const text = await resp.text();
  if (!text) return {};
  try { return JSON.parse(text); }
  catch (e) { return { ok: false, error: "响应不是 JSON：" + text.slice(0, 200) }; }
}

function showBanner(msg, isInfo) {
  const el = $("banner");
  if (!msg) { el.className = "banner"; el.textContent = ""; return; }
  el.className = "banner show" + (isInfo ? " info" : "");
  el.textContent = msg;
}

// ── 配置 ────────────────────────────────────────────────
function proxyMode() {
  const el = document.querySelector('input[name="proxymode"]:checked');
  return el ? el.value : "none";
}

function syncProxyVisibility() {
  const mode = proxyMode();
  $("wrap-proxy").style.display = mode === "single" ? "block" : "none";
  $("wrap-proxy-file").style.display = mode === "file" ? "block" : "none";
}

function readForm() {
  return {
    count: parseInt($("cfg-count").value || "1", 10),
    concurrency: parseInt($("cfg-concurrency").value || "1", 10),
    email_file: $("cfg-email-file").value.trim(),
    proxy_mode: proxyMode(),
    proxy: $("cfg-proxy").value.trim(),
    proxy_file: $("cfg-proxy-file").value.trim(),
    mail_allow_insecure: $("cfg-insecure").checked,
    enable_2fa: $("cfg-2fa").checked,
    otp_max_wait: parseInt($("cfg-otp-wait").value || "600", 10),
    otp_poll_interval: parseInt($("cfg-otp-poll").value || "3", 10),
    live: $("cfg-live").checked
  };
}

function fillForm(cfg) {
  $("cfg-count").value = cfg.count;
  $("cfg-concurrency").value = cfg.concurrency;
  $("cfg-email-file").value = cfg.email_file || "";
  const mode = cfg.proxy_mode || "none";
  document.querySelectorAll('input[name="proxymode"]').forEach((el) => {
    el.checked = el.value === mode;
  });
  $("cfg-proxy").value = cfg.proxy || "";
  $("cfg-proxy-file").value = cfg.proxy_file || "";
  $("cfg-insecure").checked = !!cfg.mail_allow_insecure;
  $("cfg-2fa").checked = !!cfg.enable_2fa;
  $("cfg-live").checked = !!cfg.live;
  $("cfg-otp-wait").value = cfg.otp_max_wait;
  $("cfg-otp-poll").value = cfg.otp_poll_interval;
  syncProxyVisibility();
}

async function loadConfig() {
  const cfg = await api("/api/config");
  if (cfg && cfg.error) { showBanner("读取配置失败：" + cfg.error); return; }
  fillForm(cfg);
}

async function saveConfig(quiet) {
  const cfg = await api("/api/config", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(readForm())
  });
  if (!cfg || cfg.error) {
    showBanner("保存失败：" + ((cfg && cfg.error) || "未知错误"));
    return null;
  }
  fillForm(cfg);
  if (!quiet) { showBanner("配置已保存到 webui/webui_config.json", true); }
  return cfg;
}

// ── 日志 ────────────────────────────────────────────────
function classify(line) {
  if (/明文\s*http|REG_MAIL_ALLOW_INSECURE|insecure/i.test(line)) return "warn";
  if (/^\s*\[\d+\/\d+\]\s+OK\b|^注册完成:/.test(line)) return "ok";
  if (/^\s*\[\d+\/\d+\]\s+(FAIL|JOIN-ERR)\b|^本次失败:/.test(line)) return "bad";
  if (/^==|^--|^\$/.test(line)) return "sys";
  return "";
}

function appendLines(lines) {
  if (!lines || !lines.length) return;
  const box = $("logbox");
  const placeholder = box.querySelector(".mut");
  if (placeholder && box.children.length === 1) box.textContent = "";
  const frag = document.createDocumentFragment();
  const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 60;
  for (const line of lines) {
    const div = document.createElement("div");
    const cls = classify(line);
    div.className = "ln" + (cls ? " " + cls : "");
    div.textContent = line.length ? line : " ";
    frag.appendChild(div);
  }
  box.appendChild(frag);
  while (box.children.length > 2600) box.removeChild(box.firstChild);
  $("st-lines").textContent = box.children.length;
  if (atBottom || lastRunning) box.scrollTop = box.scrollHeight;
}

async function pollLog() {
  const data = await api("/api/log?offset=" + logOffset);
  if (!data || typeof data.lines === "undefined") return;
  if (data.dropped) {
    appendLines(["（太多日志，已丢弃 " + data.dropped + " 行）"]);
  }
  appendLines(data.lines);
  logOffset = data.next || 0;
}

async function pollStatus() {
  const st = await api("/api/status");
  if (!st || typeof st.running === "undefined") return;
  $("st-state").textContent = st.running ? "运行中" : "已停止";
  $("st-state").className = "v " + (st.running ? "ok" : "");
  $("st-ok").textContent = st.ok;
  $("st-fail").textContent = st.fail;
  $("st-elapsed").textContent = fmtElapsed(st.elapsed);
  $("st-conc").textContent = st.running ? st.concurrency : (st.concurrency || "-");
  $("st-total").textContent = st.total || "-";
  $("st-pid").textContent = st.pid || "-";
  $("st-mode").textContent = st.mode || "-";
  $("st-exit").textContent = (st.exit_code === null || st.exit_code === undefined) ? "-" : st.exit_code;
  $("btn-start").disabled = !!st.running;
  $("btn-stop").disabled = !st.running;
  if (lastRunning === true && st.running === false) { pollLog(); }
  lastRunning = st.running;
}

function startPolling() {
  if (logPollTimer) return;
  logPollTimer = setInterval(async () => {
    try { await pollLog(); await pollStatus(); } catch (e) { /* 网络抖动忽略 */ }
  }, 1000);
}

async function refreshNow() {
  try { await pollLog(); await pollStatus(); } catch (e) {}
}

// ── 开始 / 停止 ─────────────────────────────────────────
async function startRun() {
  showBanner("");
  const cfg = await api("/api/config", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(readForm())
  });
  if (!cfg || cfg.error) { showBanner("启动前保存配置失败：" + ((cfg && cfg.error) || "未知")); return; }

  const res = await api("/api/start", { method: "POST", body: "{}" });
  if (!res || !res.ok) {
    showBanner("启动失败：\n" + ((res && res.error) || "未知错误"));
    return;
  }
  // 新进程：清空日志窗与游标
  const box = $("logbox");
  box.textContent = "";
  logOffset = 0;
  $("st-lines").textContent = "0";
  showBanner("已启动（pid=" + res.pid + "），日志实时刷新中。", true);
  startPolling();
  await refreshNow();
}

async function stopRun() {
  const res = await api("/api/stop", { method: "POST", body: "{}" });
  if (!res || !res.ok) { showBanner("停止失败：" + ((res && res.error) || "未知错误")); return; }
  showBanner("已发送终止（taskkill /T /F，pid=" + res.pid + "）。", true);
  setTimeout(refreshNow, 400);
}

// ── 账号 ────────────────────────────────────────────────
let accountsCache = [];

function statusPill(status) {
  const cls = (status === "registered" || status === "pending_otp") ? status : "other";
  const span = document.createElement("span");
  span.className = "pill " + cls;
  span.textContent = status || "—";
  return span;
}

function renderAccounts(list) {
  accountsCache = list;
  const body = $("acc-body");
  body.textContent = "";
  if (!list.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 6; td.className = "empty";
    td.textContent = "库里还没有账号。";
    tr.appendChild(td); body.appendChild(tr);
  }
  for (const acc of list) {
    const tr = document.createElement("tr");
    tr.dataset.email = acc.email;

    const tdId = document.createElement("td");
    tdId.className = "mono"; tdId.textContent = acc.id;
    tr.appendChild(tdId);

    const tdEmail = document.createElement("td");
    tdEmail.className = "mono"; tdEmail.textContent = acc.email;
    tr.appendChild(tdEmail);

    const tdStatus = document.createElement("td");
    tdStatus.appendChild(statusPill(acc.status));
    tr.appendChild(tdStatus);

    const tdAt = document.createElement("td");
    tdAt.className = acc.has_at ? "at-yes" : "at-no";
    tdAt.textContent = acc.has_at ? "有" : "—";
    tr.appendChild(tdAt);

    const tdTime = document.createElement("td");
    tdTime.className = "mono"; tdTime.textContent = fmtTime(acc.created_at);
    tr.appendChild(tdTime);

    const tdChk = document.createElement("td");
    tdChk.className = "chk"; tdChk.dataset.chk = acc.email; tdChk.textContent = "—";
    tr.appendChild(tdChk);

    body.appendChild(tr);
  }
  const registered = list.filter((a) => a.status === "registered").length;
  const pending = list.filter((a) => a.status === "pending_otp").length;
  const withAt = list.filter((a) => a.has_at).length;
  $("acc-total").textContent = list.length;
  $("acc-registered").textContent = registered;
  $("acc-pending").textContent = pending;
  $("acc-withat").textContent = withAt;
}

async function loadAccounts() {
  const data = await api("/api/accounts");
  $("acc-note").textContent = "";
  if (Array.isArray(data)) { renderAccounts(data); return; }
  if (data && data.error) {
    $("acc-note").textContent = "读取失败：" + data.error;
    renderAccounts([]);
    return;
  }
  renderAccounts([]);
}

function paintCheck(results) {
  document.querySelectorAll("td[data-chk]").forEach((td) => {
    const email = td.getAttribute("data-chk");
    if (!Object.prototype.hasOwnProperty.call(results, email)) return;
    const value = String(results[email]);
    let cls = "chk";
    if (value === "200") cls += " s200";
    else if (/^(401|403)$/.test(value)) cls += " s-bad";
    else if (/^\d{3}$/.test(value)) cls += " s-odd";
    else cls += " s-bad";
    td.textContent = value;
    td.className = cls;
  });
}

async function checkAlive() {
  if (checkBusy) return;
  checkBusy = true;
  const btn = $("btn-check");
  btn.disabled = true;
  const old = btn.textContent;
  btn.textContent = "查活中…";
  $("acc-note").textContent = "逐个请求 chatgpt.com/backend-api/me（经 socks5-hostname），可能需要几十秒…";
  try {
    const res = await api("/api/check", { method: "POST", body: "{}" });
    if (res && res._error) {
      showBanner("查活失败：" + res._error);
      $("acc-note").textContent = res._error;
    } else if (res) {
      paintCheck(res);
      $("acc-note").textContent = "查活完成（目标 " + (res._targets || 0) +
        " 个，socks5 " + (res._socks5 || "?") + "）。";
    }
  } catch (e) {
    showBanner("查活请求异常：" + e);
  } finally {
    checkBusy = false;
    btn.disabled = false;
    btn.textContent = old;
    pollLog();
  }
}

// ── 绑定 ────────────────────────────────────────────────
document.querySelectorAll('input[name="proxymode"]').forEach((el) => {
  el.addEventListener("change", syncProxyVisibility);
});
$("btn-save").addEventListener("click", () => saveConfig(false));
$("btn-start").addEventListener("click", () => startRun().catch((e) => showBanner("异常：" + e)));
$("btn-stop").addEventListener("click", () => stopRun().catch((e) => showBanner("异常：" + e)));
$("btn-refresh").addEventListener("click", () => loadAccounts());
$("btn-check").addEventListener("click", () => checkAlive());
$("logbox").addEventListener("scroll", () => {});

(async function boot() {
  await loadConfig();
  await pollStatus();
  await loadAccounts();
  try { await api("/api/log?offset=0").then((d) => {
      if (d && d.lines) { logOffset = d.next || 0; appendLines(d.lines); }
      if (d && d.running) startPolling();
  }); } catch (e) {}
  startPolling();
})();
</script>
</body>
</html>
"""


# ───────────────────────────── HTTP ─────────────────────────────

class Handler(BaseHTTPRequestHandler):
    server_version = "sentinel-rs-webui/1.0"
    protocol_version = "HTTP/1.1"

    # 关掉逐请求 stderr 噪声（保留启动/异常信息）
    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        return

    # ── 基础响应 ────────────────────────────────────────
    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, obj, code: int = 200) -> None:
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self._send(code, data, "application/json; charset=utf-8")

    def _html(self, text: str) -> None:
        self._send(200, text.encode("utf-8"), "text/html; charset=utf-8")

    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return {}
        if length > BODY_LIMIT:
            raise ValueError("请求体过大")
        raw = self.rfile.read(length)
        if not raw.strip():
            return {}
        try:
            parsed = json.loads(raw.decode("utf-8", "replace"))
        except ValueError as exc:
            raise ValueError(f"请求体不是合法 JSON: {exc}") from exc
        return parsed if isinstance(parsed, dict) else {}

    # ── 路由 ────────────────────────────────────────────
    def do_GET(self) -> None:  # noqa: N802
        try:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            query = urllib.parse.parse_qs(parsed.query)

            if path in ("/", "/index.html"):
                self._html(HTML)
                return
            if path == "/favicon.ico":
                self._send(204, b"", "image/x-icon")
                return
            if path == "/api/config":
                self._json(load_config())
                return
            if path == "/api/status":
                self._json(RUNNER.status())
                return
            if path == "/api/log":
                try:
                    offset = int((query.get("offset") or ["0"])[0])
                except ValueError:
                    offset = 0
                self._json(RUNNER.log_page(max(0, offset)))
                return
            if path == "/api/accounts":
                self._json(fetch_accounts(resolve_db(load_config())))
                return
            if path == "/api/health":
                self._json({"ok": True, "repo": str(REPO_ROOT), "pid": os.getpid()})
                return
            self._json({"ok": False, "error": f"未知路径: {path}"}, 404)
        except Exception:  # pragma: no cover - 兜底，避免连接挂死
            self._json({"ok": False, "error": traceback.format_exc(limit=3)}, 500)

    def do_POST(self) -> None:  # noqa: N802
        try:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path

            if path == "/api/config":
                try:
                    body = self._read_json()
                except ValueError as exc:
                    self._json({"ok": False, "error": str(exc)}, 400)
                    return
                self._json(save_config(merge_config(body)))
                return

            if path == "/api/start":
                try:
                    body = self._read_json()
                except ValueError as exc:
                    self._json({"ok": False, "error": str(exc)}, 400)
                    return
                cfg = save_config(merge_config(body)) if body else load_config()
                ok, payload = RUNNER.start(cfg)
                self._json(payload, 200 if ok else 400)
                return

            if path == "/api/stop":
                ok, payload = RUNNER.stop()
                self._json(payload, 200 if ok else 400)
                return

            if path == "/api/check":
                cfg = load_config()
                self._json(check_alive(cfg))
                return

            self._json({"ok": False, "error": f"未知路径: {path}"}, 404)
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception:  # pragma: no cover
            self._json({"ok": False, "error": traceback.format_exc(limit=3)}, 500)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _tune_stdio() -> None:
    """重定向到管道/文件时用 UTF-8 输出（交互式控制台保持系统原生编码，中文才不花）。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            is_tty = stream.isatty()
        except (AttributeError, ValueError):
            is_tty = False
        if is_tty or not hasattr(stream, "reconfigure"):
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):  # pragma: no cover
            pass


def main(argv: list[str] | None = None) -> int:
    _tune_stdio()
    parser = argparse.ArgumentParser(
        description="sentinel-rs 本地 WebUI（单文件 / 纯标准库 / 离线）",
    )
    parser.add_argument("--host", default="127.0.0.1", help="监听地址（默认 127.0.0.1）")
    parser.add_argument("--port", type=int, default=8787, help="监听端口（默认 8787）")
    parser.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    parser.add_argument("--allow-remote", action="store_true",
                        help="允许绑定非回环地址（默认只允许 127.0.0.1）")
    args = parser.parse_args(argv)

    loopback = {"127.0.0.1", "localhost", "::1"}
    if args.host not in loopback and not args.allow_remote:
        print(f"[拒绝] {args.host} 不是回环地址。本工具默认只绑 127.0.0.1；"
              f"确需对外开放请加 --allow-remote。", file=sys.stderr)
        return 2

    # 首次运行落一份默认配置，方便用户直接改文件
    if not CONFIG_PATH.is_file():
        cfg = save_config(DEFAULT_CONFIG)
        print(f"[初始化] 已写入默认配置 {CONFIG_PATH}")
    else:
        cfg = load_config()

    exe, exe_err = resolve_exe(cfg)
    print("=" * 66)
    print("sentinel-rs 注册控制台（本地 WebUI）")
    print(f"  仓库根    : {REPO_ROOT}")
    print(f"  可执行文件: {exe if exe else '<缺失>'}")
    if exe is None:
        print(f"  ! {exe_err.splitlines()[0]}")
    print(f"  数据库    : {resolve_db(cfg)}")
    print(f"  配置文件  : {CONFIG_PATH}")
    print(f"  curl      : {find_curl() or '<缺失（查活不可用）>'}")
    print("=" * 66)

    try:
        httpd = Server((args.host, args.port), Handler)
    except OSError as exc:
        print(f"[错误] 无法监听 {args.host}:{args.port} —— {exc}", file=sys.stderr)
        print("       端口可能被占用，换一个：python webui\\app.py --port 9000", file=sys.stderr)
        return 1

    url = f"http://{args.host}:{args.port}/"
    print(f"  已启动: {url}")
    print("  关闭窗口 / Ctrl+C 结束。")
    print("=" * 66, flush=True)

    if not args.no_browser:
        threading.Timer(0.7, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\n[退出] 收到 Ctrl+C")
    finally:
        try:
            if RUNNER.status()["running"]:
                print("[退出] 终止仍在运行的注册进程…")
                RUNNER.stop()
        except Exception:
            pass
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
