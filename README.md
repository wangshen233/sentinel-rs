# sentinel-rs（开源版）

OpenAI 注册链路中 **Sentinel token** 的 Rust 重实现，加上一套可用 `--live` 跑通的注册流程。

- **Sentinel VM**：不依赖 Node、不加载 `sdk.js`，直接解释服务端下发的 `dx` / `collector_dx` /
  `snapshot_dx` 指令程序，产出的 `t` / `so` 与真实 `sdk.js` **逐字节一致**。
- **传输层**：`wreq`（BoringSSL），模拟真实 Chrome 的 TLS(JA3/JA4) + HTTP/2 指纹。
- **注册流程**：warmup → signin → authorize → 设密码 → 邮箱取码 → OTP 校验 → 建号 →
  workspace/callback → session →（可选）TOTP 2FA → SQLite 落库。
- **邮箱层**：只依赖一个通用 HTTP 取码契约（见下文），**不绑定任何私有邮箱服务**；
  仓库自带 `tools/mock_mail.py` 作为自建服务的参考实现。

## 目录

| 路径 | 职责 |
| --- | --- |
| `src/value.rs` | JS 值模型：数字转字符串、严格相等、JSON 序列化、对象/数组 |
| `src/vm.rs` | 寄存器表 + 36 个 handler + 执行循环 + 内建函数派发 |
| `src/env.rs` | 伪 window / document / navigator / screen / performance / storage / DOM |
| `src/token.rs` | Profile、config 25 字段、FNV-1a PoW、requirements / enforcement token |
| `src/mint.rs` | 组合入口：challenge + p + profile → `t` / `so` |
| `src/flow/` | 注册流程：HTTP、授权、邮箱取码、OTP、TOTP、SQLite |
| `src/ffi.rs` | C ABI（`cdylib`），给 Python ctypes / C# / Go 调用 |
| `src/main.rs` | CLI：`mint` / `register` |
| `tools/mock_mail.py` | 自建邮箱服务参考实现（mock），用来验证邮箱契约 |

## 构建

> ⚠️ **必须用 `build.ps1` 构建**（不要直接 `cargo build`）。
>
> 传输层是 `wreq`（BoringSSL / `btls`），构建时要**现场编译 BoringSSL**：
>
> - MSVC（VS2022 "使用 C++ 的桌面开发"）+ Windows SDK → `vcvars64.bat`
> - **nasm**（BoringSSL 的汇编模块）
> - **Strawberry Perl**（BoringSSL 的生成脚本）
> - **LLVM / libclang**（`btls-sys` 的 bindgen，需要 `LIBCLANG_PATH`）
>
> 普通 PowerShell 里直接 `cargo build` 会挂在 `btls-sys` 的 bindgen 或 `cl.exe` 上。
> `build.ps1` 会自己 `call vcvars64.bat`、导入环境变量、设置 `LIBCLANG_PATH` 与 `PATH` 再跑 cargo。
> 脚本里 `$VcVars` / `$LlvmDir` 两个路径是按常见安装位置写的，装到别处就改这两行。

```powershell
# 构建（唯一受支持的入口）
.\build.ps1

# 跑测试（同样需要 MSVC 环境，所以也走脚本）
.\build.ps1 -Test

# 额外参数透传给 cargo
.\build.ps1 --bin tls_probe

# 离线：用样例 challenge 产出 t
.\target\release\sentinel-rs.exe mint --file sample_challenge.json

# 注册（默认 dry-run，只打印请求计划）
.\target\release\sentinel-rs.exe register -n 1
```

依赖版本是钉死的：`wreq = "=0.16.1"` + `wreq-util = "=0.2.0"`（`wreq` 6.x / `wreq-util` 3.x 的组合目前编不过）。
默认 TLS emulation 是 `wreq_util::Emulation::Chrome149`，可用 `TURB_WREQ_EMULATION` 覆盖
（`Chrome149` / `Chrome146` / `Firefox148` …，大小写与 `_`/`-` 不敏感）：

```powershell
$env:TURB_WREQ_EMULATION = "Chrome146"
.\target\release\sentinel-rs.exe register --preflight --proxy socks5h://127.0.0.1:1080
```

自检指纹（打印 `ja3_hash` / `ja4`）：

```powershell
.\target\release\tls_probe.exe --proxy socks5h://127.0.0.1:1080
```

## 配置

`register` 默认 **dry-run**：只构造并打印请求计划，**不联网、不注册、不发邮件**。
只有显式设置 `SENTINEL_LIVE_REGISTER=1`（或传 `--live`）才会走真实链路。

| 变量 | 说明 | 缺省 |
| --- | --- | --- |
| `SENTINEL_LIVE_REGISTER` | `1` 才真的联网注册 | `0`（dry-run） |
| `SENTINEL_COUNT` / `REGISTER_COUNT` | 批量数量 | `1` |
| `SENTINEL_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` | 代理（`host:port` 或 `scheme://[user:pass@]host:port`） | 直连 |
| `REG_MAIL_API_BASE_URL` | 邮箱取码 API 基地址（必填，`https://`） | 无 → 不能 `--live` |
| `REG_MAIL_API_TOKEN` | 邮箱 API bearer token（可选） | 空 → 不发鉴权头 |
| `REG_MAIL_ALLOW_INSECURE` | `1` 放行回环 `http://`（本地自建 / mock） | `0` |
| `SENTINEL_ENABLE_2FA` | 注册后 enroll + activate TOTP | `0` |
| `OTP_MAX_WAIT` / `OTP_POLL_INTERVAL` | 取码等待上限 / 轮询间隔（秒） | `180` / `3` |
| `SENTINEL_DB_PATH` | SQLite 路径 | `data/sentinel-rs.db` |
| `SENTINEL_USER_AGENT` / `SENTINEL_ACCEPT_LANGUAGE` | 指纹相关 | 内置 Chrome UA / `en-US,en;q=0.9` |
| `SENTINEL_LOG` | `trace` / `debug` / `info` / `warn` / `error` / `off` | `info` |

### 代理

`--proxy` 或 `SENTINEL_PROXY`；支持 `socks5h://host:port`、`http://user:pass@host:port`。
需要**真浏览器级 TLS 指纹**，所以不要指望直连能稳定过 Cloudflare。

### 一次性看链路（不消耗邮箱）

```powershell
.\target\release\sentinel-rs.exe register --preflight --proxy socks5h://127.0.0.1:1080
```

只跑 warmup → signin → authorize init，用来确认会话能不能建立。

### 完整注册

```powershell
$env:SENTINEL_LIVE_REGISTER="1"
$env:REG_MAIL_API_BASE_URL="https://your-mail-service.example/api/v1"
$env:REG_MAIL_API_TOKEN="<你的 token，可留空>"
$env:OTP_MAX_WAIT="120"; $env:OTP_POLL_INTERVAL="3"
.\target\release\sentinel-rs.exe register -n 1 --live --proxy "socks5h://127.0.0.1:1080"
```

## 邮箱 API 契约

邮箱层只认下面这一个 HTTP 契约，服务端可以是任何实现（自建服务、云函数、现成临时邮箱服务的包装）。
`src/flow/email.rs` 是唯一实现，没有其它邮箱凭据来源。

### 环境变量

| 变量 | 必需 | 说明 |
| --- | --- | --- |
| `REG_MAIL_API_BASE_URL` | ✅ | 基地址，**必须 `https://`**。本地自建 / mock 用 `http://127.0.0.1:PORT/...` 时必须同时设置 `REG_MAIL_ALLOW_INSECURE=1`（只放行回环地址，其它 `http://` 一律拒绝） |
| `REG_MAIL_API_TOKEN` | 否 | 非空时每个请求带 `Authorization: Bearer <token>`；留空则不发鉴权头 |
| `REG_MAIL_ALLOW_INSECURE` | 否 | `1`/`true`/`yes`/`on` 才放行回环 `http://`（本地 mock 的逃生门） |

### 端点

**1）领邮箱 —— `POST {base}/mailboxes`**

请求体可选 `{"local_part": "...", "subdomain": "..."}`（服务端可忽略），成功返回 `201`：

```http
HTTP/1.1 201 Created
Content-Type: application/json

{"email": "xxx@your-domain", "code_url": "https://..."}
```

- `email` 必须含 `@`；
- `code_url` 必须是 `https://`（`REG_MAIL_ALLOW_INSECURE=1` 时也接受回环 `http://`）；
- 其它状态码按失败处理，响应体里的 `error` 字段会进日志（截断 200 字符）。

**2）取验证码 —— `GET {code_url}`**

返回 `text/html` 取码页，**最新在前**，每封邮件一张卡片：

```html
<article>
  <div class="meta">时间：2026-10-29 10:00:00</div>
  <div class="code">123456</div>
</article>
```

客户端只看两样东西：

- `class="meta"` 里的时间（`时间：YYYY-MM-DD HH:MM:SS` / `Time: ...` / 纯 ISO 都行，按 UTC 解析）；
  带时间的卡片要求时间 ≥ 发码时刻（5 秒容差），用来过滤旧码；
- `class="code"` 里的文本，从中取第一个 6 位数字（前后不能紧邻数字）。
  没有 `meta` 的卡片按"首次出现"判定（发码前已存在的码会被忽略）。

**3）可选自检 —— `GET {base}/health`**

`{"ok": true}`。只在 dry-run 的请求计划里出现，**不参与注册链路**，服务端可以不实现。

### 最简示例

一个能跑的最小服务端（完整带日志/注入/鉴权的版本见 `tools/mock_mail.py`）：

```python
import json, random
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

INBOX = {}  # mailbox_id -> [卡片 HTML, ...]

def card(code):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    return f'<article><div class="meta">时间：{ts}</div><div class="code">{code}</div></article>'

class Handler(BaseHTTPRequestHandler):
    def _send(self, status, body, ctype="application/json"):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):                      # POST /api/v1/mailboxes
        mid = f"{random.randrange(10**10):010d}"
        INBOX[mid] = [card(f"{random.randrange(10**6):06d}")]   # 真发码后 append 新卡片
        self._send(201, json.dumps({
            "email": f"u{mid}@your-domain",
            "code_url": f"http://127.0.0.1:8899/api/v1/inbox/{mid}",
        }))

    def do_GET(self):                       # GET /api/v1/inbox/<id> | /api/v1/health
        if self.path.endswith("/health"):
            return self._send(200, '{"ok": true}')
        mid = self.path.rsplit("/", 1)[-1]
        body = "<!doctype html>" + "".join(INBOX.get(mid, []))
        self._send(200 if mid in INBOX else 404, body, "text/html; charset=utf-8")

ThreadingHTTPServer(("127.0.0.1", 8899), Handler).serve_forever()
```

### 自建 / 本地联调

```powershell
# 窗口 1：起 mock（内存邮箱，不连任何真实服务）
python tools/mock_mail.py --port 8899

# 窗口 2：指向 mock（必须开逃生门，因为是 http:// 回环）
$env:REG_MAIL_ALLOW_INSECURE="1"
$env:REG_MAIL_API_BASE_URL="http://127.0.0.1:8899/api/v1"
$env:REG_MAIL_API_TOKEN="test"       # mock 用 --token test 才会校验
$env:SENTINEL_LIVE_REGISTER="1"
$env:OTP_MAX_WAIT="30"
.\target\release\sentinel-rs.exe register -n 1 --live --proxy "socks5h://127.0.0.1:1080"
```

mock 会打印每次 `新建邮箱`，客户端日志里能看到 `[email] 已领取邮箱` / `[email] 已取得验证码`。
因为 `@mock-mail.local` 不是真能收信的域名，链路会停在真正的 OpenAI 注册步骤上 ——
**这正好用来确认"邮箱层换成了通用契约且仍然工作"**。

## 已知限制

- `oauth/token` 这一步返回 `401 invalid_client` 属**预期**：`client_id` 是占位值，且 authorization code
  已被 NextAuth 消费。`access_token` 实际取自 `chatgpt.com/api/auth/session`。
- 没有"重新登录 / 刷新 token"子命令，本工具只做注册。
- `--preflight` 之外的 live 链路依赖真实代理与邮箱服务；dry-run 之外的任何网络行为都需要自己配置。
- Sentinel token 生成完全离线，但服务端 challenge 会变；只有 dry-run 计划里的 `p` 是占位符。
- SQLite 里存的是明文密码与 TOTP secret，自己保管好。

## 测试

```powershell
.\build.ps1 -Test                       # cargo test --release
```

覆盖：OTP 提取与卡片解析、TOTP 已知向量、SQLite upsert、配置解析、请求构造、dry-run 计划完整性、
邮箱契约解析（含 `http://` 回环逃生门）。全部离线，不联网。

其余对拍 / 探针脚本在 `tools/`（`compare.py`、`so_compare.py`、`token_parity.py`、`tls_probe` 等），
说明见 `tools/README.md`。

## 免责声明

本项目**仅供学习与研究**：用于理解浏览器侧反自动化 VM、TLS 指纹、注册流程的工程实现。

- 请遵守目标服务的**服务条款**与当地法律，不要用于批量注册、滥用、绕过风控或任何商业用途；
- 由使用者自行承担使用后果，作者不提供任何担保，也不对账号封禁、数据丢失等负责；
- 不要把本项目用于任何未经授权的系统。

如果你只是想验证实现细节，请使用离线 `mint` 与 `register`（dry-run），它们不产生任何网络请求。
