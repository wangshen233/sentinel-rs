#!/usr/bin/env python3
"""自建邮箱服务参考实现（mock）——用来验证 sentinel-rs 的通用邮箱取码契约。

只依赖 Python 标准库，不连任何真实邮件服务：收到的"邮件"就是内存里的一串验证码。

契约（与 src/flow/email.rs 一致）：

    POST {base}/mailboxes
        -> 201 {"email": "...", "code_url": "http://<host>:<port>/api/v1/inbox/<id>"}

    GET  {base}/inbox/<id>            (= code_url)
        -> 200 text/html，最新在前，每张卡片：
           <article><div class="meta">时间：2026-10-29 10:00:00</div>
                    <div class="code">123456</div></article>

    GET  {base}/health
        -> 200 {"ok": true}          （可选自检端点）

跑起来：

    python tools/mock_mail.py --port 8899
    # 另一个窗口：
    #   $env:REG_MAIL_ALLOW_INSECURE="1"
    #   $env:REG_MAIL_API_BASE_URL="http://127.0.0.1:8899/api/v1"
    #   $env:REG_MAIL_API_TOKEN="test"

如果设置了 --token（或 MOCK_MAIL_TOKEN），POST /mailboxes 必须带
`Authorization: Bearer <token>`；不设则接受任意请求（等价于"服务端不需要鉴权"）。
"""

from __future__ import annotations

import argparse
import html
import json
import os
import random
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

BASE_PREFIX = "/api/v1"

# mailbox_id -> {"email": str, "codes": [(ts, code), ...]}；只放内存，进程退出即清空。
MAILBOXES: dict[str, dict] = {}
LOCK = threading.Lock()


def now_utc_iso_like() -> str:
    """契约里的时间格式：`YYYY-MM-DD HH:MM:SS`（UTC，无时区后缀）。"""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def render_inbox(mailbox: dict) -> str:
    cards = []
    for ts, code in mailbox["codes"][-50:][::-1]:  # 最新在前
        cards.append(
            '<article>'
            f'<div class="meta">时间：{html.escape(ts)}</div>'
            f'<div class="code">{html.escape(code)}</div>'
            "</article>"
        )
    body = "\n".join(cards) if cards else '<article><div class="meta">时间：%s</div>'
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        f"<title>inbox {html.escape(mailbox['email'])}</title></head><body>"
        f"<h1>{html.escape(mailbox['email'])}</h1>"
        f"{body}"
        "</body></html>"
    )


class Handler(BaseHTTPRequestHandler):
    server_version = "mock-mail/1.0"
    token: str = ""

    # ── 基础工具 ────────────────────────────────────────────────────────
    def log_message(self, fmt: str, *args) -> None:  # noqa: A003 - 基类签名
        print(f"[mock-mail] {self.address_string()} {fmt % args}", flush=True)

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict) -> None:
        self._send(status, json.dumps(payload).encode("utf-8"), "application/json")

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}

    def _auth_ok(self) -> bool:
        if not self.token:
            return True
        return self.headers.get("Authorization", "") == f"Bearer {self.token}"

    # ── 路由 ────────────────────────────────────────────────────────────
    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == f"{BASE_PREFIX}/health":
            self._json(200, {"ok": True})
            return
        if path.startswith(f"{BASE_PREFIX}/inbox/"):
            mailbox_id = path[len(f"{BASE_PREFIX}/inbox/"):]
            with LOCK:
                mailbox = MAILBOXES.get(mailbox_id)
                body = render_inbox(mailbox) if mailbox else ""
            if not mailbox:
                self._json(404, {"error": "mailbox not found"})
                return
            self._send(200, body.encode("utf-8"), "text/html; charset=utf-8")
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == f"{BASE_PREFIX}/mailboxes":
            if not self._auth_ok():
                self._json(401, {"error": "unauthorized"})
                return
            body = self._read_json()
            local = str(body.get("local_part") or f"u{random.randrange(10**8):08d}")
            local = "".join(c for c in local if c.isalnum() or c in "._-") or "user"
            mailbox_id = uuid.uuid4().hex[:12]
            email = f"{local}@{os.environ.get('MOCK_MAIL_DOMAIN', 'mock-mail.local')}"
            with LOCK:
                # 开局就放一条验证码：真实链路里"发码"之后立刻能取到。
                MAILBOXES[mailbox_id] = {
                    "email": email,
                    "codes": [(now_utc_iso_like(), f"{random.randrange(10**6):06d}")],
                }
            code_url = f"http://{self.headers.get('Host', '127.0.0.1:8899')}{BASE_PREFIX}/inbox/{mailbox_id}"
            print(f"[mock-mail] new mailbox {email} -> {code_url}", flush=True)
            self._json(201, {"email": email, "code_url": code_url})
            return
        if path.startswith(f"{BASE_PREFIX}/inbox/") and path.endswith("/messages"):
            mailbox_id = path[len(f"{BASE_PREFIX}/inbox/"):-len("/messages")]
            body = self._read_json()
            code = str(body.get("code") or f"{random.randrange(10**6):06d}")
            with LOCK:
                mailbox = MAILBOXES.get(mailbox_id)
                if mailbox:
                    mailbox["codes"].append((now_utc_iso_like(), code))
            if not mailbox:
                self._json(404, {"error": "mailbox not found"})
                return
            self._json(201, {"ok": True, "code": code})
            return
        self._json(404, {"error": "not found"})


def main() -> int:
    parser = argparse.ArgumentParser(description="自建邮箱服务参考实现（mock）")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8899)
    parser.add_argument(
        "--token",
        default=os.environ.get("MOCK_MAIL_TOKEN", ""),
        help="非空则要求 Authorization: Bearer <token>",
    )
    args = parser.parse_args()

    Handler.token = args.token
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(
        f"[mock-mail] listening on http://{args.host}:{args.port}{BASE_PREFIX} "
        f"(auth: {'bearer' if args.token else 'none'})",
        flush=True,
    )
    print(
        f"[mock-mail] env: REG_MAIL_ALLOW_INSECURE=1 "
        f"REG_MAIL_API_BASE_URL=http://{args.host}:{args.port}{BASE_PREFIX}",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[mock-mail] bye", flush=True)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
