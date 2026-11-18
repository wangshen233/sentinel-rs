//! 运行期定位仓库内的资源文件（`tests/token_expected.json`、`sample_challenge.json`）。
//!
//! ## 为什么不能编译期固化路径
//!
//! 旧实现在 `token_check` / `so_check` 里写 `env!("CARGO_MANIFEST_DIR")` —— 那是
//! **编译期**展开，把构建机上的目录字符串烧进二进制。一旦项目搬家（本项目还必须
//! 经 ASCII 联接构建，见 README 的 nasm 说明），二进制就再也找不到资源：
//!
//! ```text
//! 读不到 <构建时的 ASCII 联接路径>\tests\token_expected.json:
//! 系统找不到指定的路径。 (os error 3)
//! ```
//!
//! 所以改成**运行期**按固定顺序找第一个存在的候选：
//!
//!   1. `SENTINEL_REPO_ROOT` —— 显式指定，最优先（CI / 搬家 / 只读安装场景）
//!   2. `CARGO_MANIFEST_DIR` —— `cargo run` / `cargo test` 时由 cargo 注入
//!   3. 当前工作目录
//!   4. 可执行文件所在目录，以及向上 1~3 层
//!      （`target\release\x.exe` → `target\release` → `target` → 仓库根 → 上一级）
//!
//! 找不到时返回**列出所有尝试过的路径**的错误，调用方打印后以非 0 退出。

use std::path::{Path, PathBuf};

/// 显式指定仓库根目录的环境变量。
pub const REPO_ROOT_ENV: &str = "SENTINEL_REPO_ROOT";

/// 读环境变量里的目录（空值当没有）。
fn env_dir(key: &str) -> Option<PathBuf> {
    std::env::var(key)
        .ok()
        .map(|v| PathBuf::from(v.trim()))
        .filter(|p| !p.as_os_str().is_empty())
}

/// 所有会尝试的「仓库根目录」候选，按优先级顺序、已去重。
pub fn repo_root_candidates() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut push = |path: PathBuf| {
        let key = path.to_string_lossy().to_ascii_lowercase();
        if out
            .iter()
            .any(|seen| seen.to_string_lossy().to_ascii_lowercase() == key)
        {
            return;
        }
        out.push(path);
    };

    // 1) 显式指定
    if let Some(dir) = env_dir(REPO_ROOT_ENV) {
        push(dir);
    }
    // 2) cargo 注入（运行期读取，不是 env! 宏）
    if let Some(dir) = env_dir("CARGO_MANIFEST_DIR") {
        push(dir);
    }
    // 3) 当前工作目录
    if let Ok(cwd) = std::env::current_dir() {
        push(cwd);
    }
    // 4) 可执行文件所在目录 + 向上 3 层
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe.parent().map(Path::to_path_buf);
        for _ in 0..4 {
            let Some(current) = dir else { break };
            push(current.clone());
            dir = current.parent().map(Path::to_path_buf);
        }
    }
    out
}

/// 在候选根目录里找 `rel`，返回第一个存在的文件（绝对路径尽量保留）。
pub fn find_repo_file(rel: impl AsRef<Path>) -> Result<PathBuf, String> {
    let rel = rel.as_ref();
    let mut tried: Vec<PathBuf> = Vec::new();
    for root in repo_root_candidates() {
        let candidate = root.join(rel);
        if candidate.is_file() {
            return Ok(candidate);
        }
        tried.push(candidate);
    }
    let list = tried
        .iter()
        .map(|p| format!("  - {}", p.display()))
        .collect::<Vec<_>>()
        .join("\n");
    Err(format!(
        "找不到仓库文件 {}（可用环境变量 {} 显式指定仓库根目录）。尝试过:\n{list}",
        rel.display(),
        REPO_ROOT_ENV
    ))
}

/// 同 [`find_repo_file`]，但给定的显式路径存在时直接用它（命令行参数优先）。
pub fn resolve_optional(explicit: Option<&str>, rel: &str) -> Result<PathBuf, String> {
    if let Some(raw) = explicit.map(str::trim).filter(|v| !v.is_empty()) {
        let path = PathBuf::from(raw);
        if path.is_file() {
            return Ok(path);
        }
        // 显式给了但写错：仍然尝试按仓库相对路径找一次，再报错
        if let Ok(found) = find_repo_file(rel) {
            return Ok(found);
        }
        return Err(format!("指定的文件不存在: {}", path.display()));
    }
    find_repo_file(rel)
}
