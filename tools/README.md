# tools/ —— Rust VM 与 Python oracle 的字节级对齐工具

目标：`sample_challenge.json` 上 Rust 版与 `sentinel_vm.py` 产出**逐字节相同**的
`t`，且 `steps` 相同（当前：426 / 426，t 长度 944，944）。

## 一键验证

```powershell
cd <repo 根目录>
cargo build --release
python tools\compare.py            # steps + t 全量比较，输出 equal=True
python tools\compare.py --trace    # 再逐行 diff 1973 行“每条指令 + 每次寄存器写入”轨迹
python tools\verify_acceptance.py  # 端到端：跑发布版二进制，与 oracle 比 sha256
```

`compare.py` 的 Rust 侧是 `target/release/sentinel-trace.exe`
（源码 `src/bin/sentinel-trace.rs`，与发布版 `sentinel-rs` 走同一条 VM 路径，
只是额外打印完整 `t` 与可选 trace）。

换一组 pin 再对比（两边都读同名环境变量，用于确认 parity 不是“单点巧合”）：

```powershell
$env:SENTINEL_PIN_RANDOM="0.7231837"; $env:SENTINEL_PIN_PERF_NOW="42.25"
$env:SENTINEL_PIN_CLOCK_MS="1793036746210"; python tools\compare.py
```

## 环境变量（脚本不含任何绝对路径默认值）

| 变量 | 用途 | 缺省 |
|---|---|---|
| `SENTINEL_ORACLE_DIR` / `SENTINEL_PY_DIR` | Python oracle 目录（含 `sentinel_vm.py` / `sentinel_py.py`） | **必须设置**，否则脚本直接报错退出 |
| `SRS_DLL` | 待分析的 DLL（`dll_check` / `decompile_scan` / `dll_memory_probe` / `dll_only_probe` / `dll_coldstart_probe`） | `target/release/sentinel_rs.dll`（相对当前工作目录） |
| `SRS_DLL_VMP` | VMProtect 加壳版 DLL（`dll_security_check` 的对照组） | 未设置则跳过该组 |
| `SRS_SAMPLE` | challenge 样例路径 | `sample_challenge.json`（相对当前工作目录） |

```powershell
$env:SENTINEL_ORACLE_DIR = "<你的 Python oracle 目录>"
$env:SRS_DLL             = "target\release\sentinel_rs.dll"
```

## 文件

| 文件 | 作用 |
|---|---|
| `pyoracle.py` | 确定性 Python oracle：把 `Math.random`/`crypto`/`Date.now`/`performance.now`/`__oai_so_*` 全部 pin 死（`SENTINEL_ORACLE_DIR` 可指定 oracle 目录） |
| `dump_env.py` | 把 Python `VM(ctx).window` 递归导出成 `src/env_dump.json`（Rust 用 `include_str!` 加载） |
| `compare.py` | 跑两边、比较 `steps`/`t`、可选 diff trace，打印首个差异位置与上下文 |
| `verify_acceptance.py` | 端到端验收：直接跑 `target/release/sentinel-rs.exe`，比对 t 的 sha256 |
| `py_writes.py` | Python 侧“每条指令 + 每次 set”轨迹（`tools/py_writes.py -` 直接打印） |
| `hits.py` | 统计 dx 程序读过的所有环境属性（用于确认哪些 stub 方法真的被调用） |
| `inspect_oracle.py` | 跑一遍 oracle，打印 misses / reads / 载荷长度 |
| `show_env.py` / `peek.py` | 查看 `env_dump.json` 的键序与子树 |
| `mock_mail.py` | **自建邮箱服务参考实现**：实现 `src/flow/email.rs` 的通用取码契约（`POST /mailboxes` + `GET {code_url}`），仅标准库，用于本地联调注册链路 |
| `dll_check.py` | ctypes 直接调 DLL 导出：requirements / `t` / `so` / `register`（dry-run，`SRS_LIVE=1` 才真注册） |
| `decompile_scan.py` | 对 DLL 做定向反汇编：定位导出函数与关键字符串引用点 |
| `dll_memory_probe.py` | 同进程内存扫描：DLL 跑起来后还能捞到多少明文标记 |
| `dll_only_probe.py` / `dll_coldstart_probe.py` | “只拿到一个 DLL”的冷启动探测：干净目录 + 干净环境能试探出什么 |
| `dll_security_check.py` | 静态安全性检查：原版 vs VMProtect 加壳版（两组路径都走 `SRS_DLL` / `SRS_DLL_VMP`） |

## oracle 的随机因素（必须 pin，否则 t 每次都变）

`sentinel_vm.py` 自己会调用 `random.random()`（Math.random）、`os.urandom()`
（crypto.getRandomValues）、`uuid.uuid4()`、`time.time()`/`time.perf_counter()`
（Date.now / performance.now 基线）以及 `random.randint()`（`__oai_so_*`）。
`pyoracle.patch()` 在**构造环境之前**统一 pin 成：

```
Date.now()        = 1700000000000
performance.now() = 15.5
Math.random()     = 0.5
random.randint(a, b) = a        # __oai_so_* 取下界
os.urandom(n)     = b"\x00"*n
uuid.uuid4()      = 00000000-0000-4000-8000-000000000000
```

Rust 侧对应的常量在 `src/vm.rs::Vm::new`（`clock_now` / `perf_now` / `random`）
与 `src/env_dump.json`（dump 时就已 pin 好的字段）。

> 因此 t 长度是 **944**。未 pin 的 Python 是 992/996（`Math.random()` 的小数位数
> 不同 → 数字进载荷后长度不同），pin 成 0.5 后两边都稳定在 944。

## 重新生成环境（改 Python oracle 环境后必须重跑）

```powershell
python tools\dump_env.py     # → src/env_dump.json（保持插入顺序）
cargo build --release
python tools\compare.py --trace
```

`env_dump.json` 的节点约定：

| 标记 | 含义 |
|---|---|
| `{"$o": [[k, v], ...]}` | 有序键值对（serde_json 的 map 会按键排序，所以顺序放在数组里） |
| `{"$fn": path, "$b": behaviour}` | 环境函数；Rust 按 `$b`（如 `ElementStub.appendChild`）派发 |
| `{"$self": true}` | 回指 window（self/top/parent/globalThis） |
| `{"$k": "d"/"p"}` | `d` = Python dict（可 JSON 序列化）；`p` = stub 实例（`JSON.stringify` 得 `null`） |
| `{"$wild": "noop"}` | Python 侧带 `__getattr__` 兜底的 stub（`_Ctx2D` / `_WebGL`） |
| `{"$num": "NaN"}` | JSON 无法表示的非有限浮点 |
