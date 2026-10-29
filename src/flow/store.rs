//! rusqlite 持久化：建表 + 账号落库。
//!
//! 表结构对齐 Python `core/db.py` 的 `accounts` 语义（email 唯一、状态、时间），
//! 但把常用字段（password / access_token / 2fa secret / cookies）拍平成列，
//! 便于 Rust 侧直接查询（Python 侧是 `payload` JSON 一列）。
//!
//! 时间统一存 unix 秒（`TEXT` 列里放十进制数字），避免引入 chrono。

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const SCHEMA_VERSION: i64 = 1;

/// 一条注册结果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Account {
    pub email: String,
    pub password: String,
    pub access_token: String,
    /// TOTP secret（base32）；没绑 2FA 时为空串。
    pub totp_secret: String,
    /// Cookie 头或 cookie JSON。
    pub cookies: String,
    /// `pending` / `registered` / `failed` …
    pub status: String,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Account {
    pub fn new(email: impl Into<String>, password: impl Into<String>) -> Self {
        let now = now_ts();
        Self {
            email: email.into(),
            password: password.into(),
            status: "pending".to_string(),
            created_at: now,
            updated_at: now,
            ..Default::default()
        }
    }
}

/// SQLite 句柄（`Connection` 不是 Sync，单线程用）。
pub struct Store {
    conn: Connection,
}

impl Store {
    /// 打开文件库（自动建父目录）。
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("创建数据库目录失败: {}", parent.display()))?;
            }
        }
        let conn = Connection::open(path)
            .with_context(|| format!("打开 SQLite 失败: {}", path.display()))?;
        // 并发注册时多个进程/任务同时写库：WAL + busy_timeout 避免 SQLITE_BUSY 丢记录。
        conn.busy_timeout(std::time::Duration::from_secs(15))
            .context("设置 SQLite busy_timeout 失败")?;
        Ok(Self { conn })
    }

    /// 内存库（单测用）。
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("打开内存 SQLite 失败")?;
        Ok(Self { conn })
    }

    /// 建表 + 索引（幂等）。
    pub fn init(&self) -> Result<()> {
        self.conn
            .execute_batch(
                r#"
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = NORMAL;

                CREATE TABLE IF NOT EXISTS accounts (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    email         TEXT    NOT NULL UNIQUE,
                    password      TEXT    NOT NULL DEFAULT '',
                    access_token  TEXT    NOT NULL DEFAULT '',
                    totp_secret   TEXT    NOT NULL DEFAULT '',
                    cookies       TEXT    NOT NULL DEFAULT '',
                    status        TEXT    NOT NULL DEFAULT 'pending',
                    created_at    INTEGER NOT NULL DEFAULT 0,
                    updated_at    INTEGER NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_accounts_status  ON accounts(status, id DESC);
                CREATE INDEX IF NOT EXISTS idx_accounts_created ON accounts(created_at DESC);

                CREATE TABLE IF NOT EXISTS email_pool (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    email       TEXT NOT NULL UNIQUE,
                    code_url    TEXT NOT NULL DEFAULT '',
                    source      TEXT NOT NULL DEFAULT 'mail_api',
                    status      TEXT NOT NULL DEFAULT 'available',
                    created_at  INTEGER NOT NULL DEFAULT 0,
                    updated_at  INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS schema_meta (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                "#,
            )
            .context("初始化 schema 失败")?;
        self.conn
            .execute(
                "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![SCHEMA_VERSION.to_string()],
            )
            .context("写入 schema_version 失败")?;
        Ok(())
    }

    /// 保存账号（按 email upsert），返回行 id。
    pub fn save_account(&self, account: &Account) -> Result<i64> {
        if account.email.trim().is_empty() {
            anyhow::bail!("account.email 不能为空");
        }
        let updated_at = if account.updated_at == 0 {
            now_ts()
        } else {
            account.updated_at
        };
        let created_at = if account.created_at == 0 {
            updated_at
        } else {
            account.created_at
        };
        self.conn
            .execute(
                "INSERT INTO accounts
                    (email, password, access_token, totp_secret, cookies, status, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(email) DO UPDATE SET
                    password     = excluded.password,
                    access_token = excluded.access_token,
                    totp_secret  = excluded.totp_secret,
                    cookies      = excluded.cookies,
                    status       = excluded.status,
                    updated_at   = excluded.updated_at",
                params![
                    account.email,
                    account.password,
                    account.access_token,
                    account.totp_secret,
                    account.cookies,
                    account.status,
                    created_at,
                    updated_at,
                ],
            )
            .context("写入 accounts 失败")?;
        self.conn
            .query_row(
                "SELECT id FROM accounts WHERE email = ?1",
                params![account.email],
                |row| row.get::<_, i64>(0),
            )
            .context("读取刚写入账号的 id 失败")
    }

    pub fn get_account(&self, email: &str) -> Result<Option<Account>> {
        self.conn
            .query_row(
                "SELECT email, password, access_token, totp_secret, cookies, status, created_at, updated_at
                 FROM accounts WHERE email = ?1",
                params![email],
                row_to_account,
            )
            .optional()
            .context("查询 accounts 失败")
    }

    pub fn list_accounts(&self, limit: usize) -> Result<Vec<Account>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT email, password, access_token, totp_secret, cookies, status, created_at, updated_at
                 FROM accounts ORDER BY id DESC LIMIT ?1",
            )
            .context("准备查询语句失败")?;
        let rows = stmt
            .query_map(params![limit as i64], row_to_account)
            .context("查询 accounts 失败")?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.context("读取 accounts 行失败")?);
        }
        Ok(out)
    }

    pub fn count(&self) -> Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM accounts", [], |row| row.get::<_, i64>(0))
            .context("统计 accounts 失败")
    }

    pub fn schema_version(&self) -> Result<i64> {
        let raw: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .optional()
            .context("读取 schema_version 失败")?;
        Ok(raw.and_then(|v| v.parse().ok()).unwrap_or(0))
    }
}

fn row_to_account(row: &rusqlite::Row<'_>) -> rusqlite::Result<Account> {
    Ok(Account {
        email: row.get(0)?,
        password: row.get(1)?,
        access_token: row.get(2)?,
        totp_secret: row.get(3)?,
        cookies: row.get(4)?,
        status: row.get(5)?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
    })
}

/// 当前 unix 秒。
pub fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
