//! mailbox 的持久化层：消息队列的 SQLite 存储与 TTL 清理。

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use rusqlite::{params, Connection as SqlConn, OptionalExtension};
use tokio::sync::Mutex;

/// 队列存储 + SQLite 持久化。
///
/// 两张表：
/// - `queues`：队列 id → `sender_auth` / `owner_auth`（写权限与读权限公钥）、
///   创建时间；取回即删时连队列一起删。
/// - `queue_msgs`：`(queue_id, seq)` 主键，`seq` 由节点按写入顺序递增，
///   `payload` 是应用层密文，`time` 用于 TTL 清理。
///
/// 只存密文、队列 id 与公钥，节点不接触明文。
#[derive(Clone)]
pub(crate) struct MailboxStore {
    pub(crate) conn: Arc<Mutex<SqlConn>>,
    pub(crate) path: PathBuf,
    /// 消息最长保留秒数；0 = 永不过期。
    ttl_secs: u64,
    /// 单队列消息条数上限（防灌满）。
    max_queue_msgs: usize,
    /// 单队列总字节上限。
    max_queue_bytes: usize,
    /// 节点上队列总数的上限（空的队列也算，防被人拿 create 刷爆库）。
    max_queues: usize,
}

/// 节点默认最多留多少个队列。
const DEFAULT_MAX_QUEUES: usize = 50_000;

impl std::fmt::Debug for MailboxStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailboxStore")
            .field("path", &self.path)
            .finish()
    }
}

impl MailboxStore {
    /// 打开（或创建）当前版本 SQLite 库并建立表结构。
    pub(crate) fn open(path: PathBuf, ttl_secs: u64) -> Result<Self> {
        Self::open_with_limits(path, ttl_secs, 1000, 64 * 1024 * 1024, DEFAULT_MAX_QUEUES)
    }

    /// 指定队列限额打开（测试或运营自定义用）。
    pub(crate) fn open_with_limits(
        path: PathBuf,
        ttl_secs: u64,
        max_queue_msgs: usize,
        max_queue_bytes: usize,
        max_queues: usize,
    ) -> Result<Self> {
        let conn = SqlConn::open(&path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS queues (
                 queue_id TEXT PRIMARY KEY,
                 sender_auth BLOB NOT NULL,
                 owner_auth BLOB NOT NULL,
                 created INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS queue_msgs (
                 queue_id TEXT NOT NULL,
                 seq INTEGER NOT NULL,
                 payload BLOB NOT NULL,
                 time INTEGER NOT NULL,
                 PRIMARY KEY (queue_id, seq)
             );
",
        )?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            path,
            ttl_secs,
            max_queue_msgs,
            max_queue_bytes,
            max_queues,
        })
    }

    /// 创建单向队列；已存在则返回 false（先到先得）。
    pub(crate) async fn create_queue(
        &self,
        queue_id: &str,
        sender_auth: &[u8],
        owner_auth: &[u8],
        now: u64,
    ) -> Result<bool> {
        let conn = self.conn.lock().await;
        let queues: i64 = conn.query_row("SELECT COUNT(*) FROM queues", [], |row| row.get(0))?;
        if queues as usize >= self.max_queues {
            return Err(anyhow!(
                "node queue capacity reached ({} queues)",
                self.max_queues
            ));
        }
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO queues (queue_id, sender_auth, owner_auth, created)
             VALUES (?1, ?2, ?3, ?4)",
            params![queue_id, sender_auth, owner_auth, now as i64],
        )?;
        Ok(inserted == 1)
    }

    /// 取队列的两把公钥：`(sender_auth, owner_auth)`。
    pub(crate) async fn queue_auth(&self, queue_id: &str) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let conn = self.conn.lock().await;
        let row = conn
            .query_row(
                "SELECT sender_auth, owner_auth FROM queues WHERE queue_id = ?1",
                params![queue_id],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        Ok(row)
    }

    /// 换掉队列登记的 sender 公钥（吊销旧邀请时用）。
    pub(crate) async fn update_queue_sender(
        &self,
        queue_id: &str,
        sender_auth: &[u8],
    ) -> Result<usize> {
        let conn = self.conn.lock().await;
        let changed = conn.execute(
            "UPDATE queues SET sender_auth = ?2 WHERE queue_id = ?1",
            params![queue_id, sender_auth],
        )?;
        Ok(changed)
    }

    /// 往队列追加一条密文，返回序号。
    pub(crate) async fn push_queue(&self, queue_id: &str, payload: &[u8], now: u64) -> Result<i64> {
        let conn = self.conn.lock().await;
        // 单队列限额：条数 + 总字节（防灌满）
        let (count, bytes): (i64, i64) = conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(LENGTH(payload)), 0) FROM queue_msgs WHERE queue_id = ?1",
            params![queue_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if count as usize >= self.max_queue_msgs {
            return Err(anyhow!("queue full: {} messages", self.max_queue_msgs));
        }
        if bytes as usize + payload.len() > self.max_queue_bytes {
            return Err(anyhow!("queue full: {} bytes", self.max_queue_bytes));
        }
        let seq: i64 = conn.query_row(
            "SELECT COALESCE(MAX(seq), 0) + 1 FROM queue_msgs WHERE queue_id = ?1",
            params![queue_id],
            |row| row.get(0),
        )?;
        conn.execute(
            "INSERT INTO queue_msgs (queue_id, seq, payload, time) VALUES (?1, ?2, ?3, ?4)",
            params![queue_id, seq, payload, now as i64],
        )?;
        Ok(seq)
    }

    /// 取走队列全部消息（按 seq 升序）并删除。
    pub(crate) async fn take_queue(&self, queue_id: &str) -> Result<Vec<(i64, Vec<u8>)>> {
        let conn = self.conn.lock().await;
        let mut out = Vec::new();
        {
            let mut stmt = conn
                .prepare("SELECT seq, payload FROM queue_msgs WHERE queue_id = ?1 ORDER BY seq")?;
            let rows = stmt.query_map(params![queue_id], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?;
            for r in rows {
                out.push(r?);
            }
        }
        conn.execute(
            "DELETE FROM queue_msgs WHERE queue_id = ?1",
            params![queue_id],
        )?;
        Ok(out)
    }

    /// 删除队列及其消息。
    pub(crate) async fn delete_queue(&self, queue_id: &str) -> Result<usize> {
        let conn = self.conn.lock().await;
        conn.execute(
            "DELETE FROM queue_msgs WHERE queue_id = ?1",
            params![queue_id],
        )?;
        let n = conn.execute("DELETE FROM queues WHERE queue_id = ?1", params![queue_id])?;
        Ok(n)
    }

    /// 删除已超过 TTL 的消息，返回删除行数。
    pub(crate) async fn purge_expired(&self, now_ms: u64) -> Result<usize> {
        if self.ttl_secs == 0 {
            return Ok(0);
        }
        let cutoff = now_ms.saturating_sub(self.ttl_secs * 1000);
        let conn = self.conn.lock().await;
        let deleted = conn.execute(
            "DELETE FROM queue_msgs WHERE time < ?1",
            params![cutoff as i64],
        )?;
        Ok(deleted)
    }
}
