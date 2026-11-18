# sentinel-rs 本地 WebUI

给 `sentinel-rs register` 套的一层**本地网页控制台**。单文件 `app.py`，只用 Python 标准库
（`http.server` / `sqlite3` / `subprocess` / `threading` / `json` / `urllib`），
不引任何 pip 依赖、不引任何 CDN，断网也能用。

```
webui/
├─ app.py              # 全部后端 + 内嵌的 HTML/CSS/JS（单文件）
├─ README.md           # 本文件
└─ webui_config.json   # 首次启动自动生成，UI 的「保存配置」写这里
```

## 快速开始

```bat
cd /d "<仓库根目录>"
python webui\app.py                :: 默认 127.0.0.1:8787，自动开浏览器
python webui\app.py --port 9000    :: 换端口
python webui\app.py --no-browser   :: 不自动开浏览器（自己点控制台里的地址）
```

启动后控制台会打印地址与关键路径，例如：

```
==================================================================
sentinel-rs 注册控制台（本地 WebUI）
  仓库根    : ...\sentinel-rs-main
  可执行文件: ...\sentinel-rs-main\target\release\sentinel-rs.exe
  数据库    : ...\sentinel-rs-main\data\sentinel-rs.db
  配置文件  : ...\sentinel-rs-main\webui\webui_config.json
  curl      : C:\windows\system32\curl.exe
==================================================================
  已启动: http://127.0.0.1:8787/
```

前提：`target\release\sentinel-rs.exe` 已经构建好（`build.ps1` 或 `cargo build --release`）。
找不到时 `POST /api/start` 会返回明确错误，而不是静默失败。

## 界面能做什么

| 区块 | 说明 |
| --- | --- |
| 顶部状态条 | 状态（运行中/已停止）、成功数、失败数、已跑时长、当前并发、总数 |
| 配置面板 | `-n`、`-c`、`--email-file`、代理三选一、`REG_MAIL_ALLOW_INSECURE`、`SENTINEL_ENABLE_2FA`、`OTP_MAX_WAIT`、`OTP_POLL_INTERVAL`、LIVE 开关 |
| 实时日志 | 子进程 stdout+stderr 合并，`[n/total] OK\|FAIL` 绿色/红色，**明文 http 警告黄色**，1 秒增量刷新并自动滚到底 |
| 账号列表 | 只读 `data/sentinel-rs.db` 的 `accounts`：id / email / status / 有无 AT / 创建时间，顶部有总数、registered、pending_otp、有 AT 统计 |
| 查活 | 对每个有 AT 的账号跑 `curl --socks5-hostname 127.0.0.1:10808 -H "authorization: Bearer <AT>" https://chatgpt.com/backend-api/me`，结果显示在表格最后一列（**不落库**） |

默认 **dry-run**（不联网、不消耗邮箱）。勾选 `SENTINEL_LIVE_REGISTER=1` 并点「开始注册」
才会真实建号 —— 这一步会消耗邮箱清单，请确认后再点。

## 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/` | 页面（单文件 HTML，内嵌 CSS/JS） |
| GET | `/api/config` | 读配置 |
| POST | `/api/config` | 写配置（非法值自动钳制：count≥1、proxy_mode 只认 none/single/file） |
| POST | `/api/start` | 启动注册，返回 `{ok, pid}` 或 `{ok:false, error}`；body 可带配置（先存再启动） |
| POST | `/api/stop` | `taskkill /PID <pid> /T /F` 终止整棵进程树 |
| GET | `/api/status` | `{running, elapsed, ok, fail, total, pid, concurrency, mode, exit_code}` |
| GET | `/api/log?offset=N` | `{lines:[...], next:N, dropped:N}`，`offset` 是绝对行号，可安全增量拉取 |
| GET | `/api/accounts` | 账号数组（成功时是纯数组；读库失败时返回 `{ok:false, error}`） |
| POST | `/api/check` | 逐个查活，返回 `{email: "200"}`，附带 `_curl/_socks5/_targets/_error` 元信息 |
| GET | `/api/health` | 存活探针 |

## 行为细节

* **只绑回环**：默认 `127.0.0.1`；`--host 0.0.0.0` 之类会被拒绝（exit 2），
  确需对外开放得显式加 `--allow-remote`。
* **单进程**：同一时刻只允许一个注册进程；运行中再点「开始」返回
  `已有注册进程在运行（pid=...），请先点「停止」`。
* **子进程隔离**：`Popen(..., cwd=<仓库根>, env=<新建的 dict>)`。父进程 `os.environ`
  不会被改动；同时先剥掉可能干扰的继承变量（`SENTINEL_PROXY*`、`HTTPS_PROXY`、
  `REG_MAIL_*`、`OTP_*`、`SENTINEL_LIVE_REGISTER` 等），再按 UI 配置注入。
* **代理口令不进程命令行**：单代理走 `SENTINEL_PROXY` 环境变量注入而不是 `--proxy`
  参数，避免口令出现在任务管理器 / 进程列表里；日志回显里的 `user:pass@` 也会被打成 `***`。
* **日志缓冲**：环形缓冲保留最近 2000 行，`next` 是绝对行号；超出部分前端会提示丢弃行数。
* **只读数据库**：`sqlite3` 以 `mode=ro` + URI 打开，绝不写库；AT 只在服务端读取，
  不下发给浏览器。（库是 WAL 模式，只读连接可能留下 `sentinel-rs.db-shm` /
  `sentinel-rs.db-wal` 旁文件，属 SQLite 正常行为，不影响数据。）
* **查活依赖 curl**：用 Windows 10+ 自带的 `curl.exe`（或 PATH 里的 curl），
  找不到时按钮返回明确错误。

## 常见问题

| 现象 | 处理 |
| --- | --- |
| `[错误] 无法监听 127.0.0.1:8787` | 端口被占，换 `--port 9000`。 |
| `找不到 sentinel-rs 可执行文件` | 先 `build.ps1` 或 `cargo build --release`；也可在 `webui_config.json` 里把 `exe` 指到别处。 |
| 点「开始」立刻 failed，日志里 `错误: --email-file 指向的文件不存在` | 配置里的邮箱清单路径写错了（UI 也会在启动前拦住）。 |
| 账号表打不开 | 数据库被注册进程独占写入，稍后点「刷新」。 |
| 查活全 `错误(rc=7)` | `127.0.0.1:10808` 的 socks5 没开，或把 `check_socks5` 改成自己的代理。 |
| 日志区一直空 | 进程没启动成功（看顶部横幅的错误），或浏览器拦了 `fetch`。 |

## 配置字段（`webui_config.json`）

```json
{
  "count": 1,                       // -n
  "concurrency": 1,                 // -c
  "email_file": "...mails.txt",     // --email-file
  "proxy_mode": "none",             // none | single | file
  "proxy": "",                      // single 模式的代理地址
  "proxy_file": "...proxies.txt",   // file 模式的代理清单
  "mail_allow_insecure": false,     // REG_MAIL_ALLOW_INSECURE=1
  "enable_2fa": false,              // SENTINEL_ENABLE_2FA
  "otp_max_wait": 600,              // OTP_MAX_WAIT
  "otp_poll_interval": 3,           // OTP_POLL_INTERVAL
  "live": false,                    // true → SENTINEL_LIVE_REGISTER=1
  "log_level": "info",              // SENTINEL_LOG
  "exe": "",                        // 留空 = 自动找 target/release|debug
  "db_path": "",                    // 留空 = data/sentinel-rs.db
  "check_socks5": "127.0.0.1:10808",
  "check_timeout": 20
}
```

文件里只有**路径**默认值，没有任何邮箱内容、代理口令或 token —— 凭据始终留在
你自己的清单文件和数据库里。
