//! mailbox 的持久化层：消息队列的 SQLite 存储与 TTL 清理。

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use rusqlite::{params, Connection as SqlConn, OptionalExtension};
use tokio::sync::Mutex;

use privchat_common::StoredMessage;

/// 内存邮箱 + SQLite 持久化。
///
/// 单表 `messages`：
/// - `msg_id`      TEXT —— 发送方派生 ID，与 to_peer_id 组成主键，去重 + 排序
/// - `to_peer_id`  TEXT NOT NULL —— 接收方身份（按此分类队列）
/// - `msg`         BLOB NOT NULL —— 应用层密文
/// - `time`        INTEGER NOT NULL —— 入库时间（毫秒），TTL 到期清除依据
///
/// 另建 `idx_messages_to` 索引加速按接收方拉取。仅存密文与路由元数据，
/// 节点不接触明文。
#[derive(Clone)]
pub(crate) struct MailboxStore {
    pub(crate) conn: Arc<Mutex<SqlConn>>,
    pub(crate) path: PathBuf,
    /// 消息最长保留秒数；0 = 永不过期。
    ttl_secs: u64,
}

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
             CREATE TABLE IF NOT EXISTS messages (
                 msg_id      TEXT NOT NULL,
                 to_peer_id  TEXT NOT NULL,
                 msg         BLOB NOT NULL,
                 time        INTEGER NOT NULL DEFAULT 0,
                 PRIMARY KEY (to_peer_id, msg_id)
             );
             CREATE INDEX IF NOT EXISTS idx_messages_to ON messages(to_peer_id);",
        )?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            path,
            ttl_secs,
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

    /// 往队列追加一条密文，返回序号。
    pub(crate) async fn push_queue(&self, queue_id: &str, payload: &[u8], now: u64) -> Result<i64> {
        let conn = self.conn.lock().await;
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

    /// 存入一条消息；同一 (接收方,msg_id,payload) 幂等，不同 payload 冲突。
    pub(crate) async fn put(&self, msg: StoredMessage, time: u64) -> Result<bool> {
        let conn = self.conn.lock().await;
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO messages (msg_id, to_peer_id, msg, time) VALUES (?1, ?2, ?3, ?4)",
            params![msg.msg_id, msg.to_peer_id, msg.msg, time as i64],
        )?;
        if inserted == 1 {
            return Ok(true);
        }
        let same_payload: bool = conn.query_row(
            "SELECT msg = ?3 FROM messages WHERE to_peer_id = ?1 AND msg_id = ?2",
            params![msg.to_peer_id, msg.msg_id, msg.msg],
            |row| row.get(0),
        )?;
        if same_payload {
            Ok(false)
        } else {
            Err(anyhow!("msg_id conflict with different payload"))
        }
    }

    /// 拉取某接收方队列的全部密文（按 `msg_id` 升序），返回后**立即删除**
    /// （取回即删）。调用方负责向 peer 广播删除意图。
    pub(crate) async fn fetch(&self, recipient: &str) -> Result<Vec<StoredMessage>> {
        let conn = self.conn.lock().await;
        let mut out = Vec::new();
        {
            let mut stmt = conn.prepare(
                "SELECT msg_id, to_peer_id, msg FROM messages WHERE to_peer_id = ?1 ORDER BY msg_id",
            )?;
            let rows = stmt.query_map(params![recipient], |row| {
                Ok(StoredMessage {
                    msg_id: row.get(0)?,
                    to_peer_id: row.get(1)?,
                    msg: row.get(2)?,
                })
            })?;
            for r in rows {
                out.push(r?);
            }
        }
        if !out.is_empty() {
            let ids: Vec<String> = out.iter().map(|m| m.msg_id.clone()).collect();
            let placeholders = vec!["?"; ids.len()].join(",");
            let sql = format!(
                "DELETE FROM messages WHERE to_peer_id = ?1 AND msg_id IN ({placeholders})"
            );
            let mut stmt = conn.prepare(&sql)?;
            stmt.raw_bind_parameter(1, recipient)?;
            for (i, id) in ids.iter().enumerate() {
                stmt.raw_bind_parameter(i + 2, id)?;
            }
            stmt.raw_execute()?;
        }
        Ok(out)
    }

    /// 取出全部待收密文（PEX 学习到新节点时的一次性补推，带上限）。
    pub(crate) async fn list_all(&self, limit: usize) -> Result<Vec<StoredMessage>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn
            .prepare("SELECT msg_id, to_peer_id, msg FROM messages ORDER BY time DESC LIMIT ?1")?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(StoredMessage {
                msg_id: row.get(0)?,
                to_peer_id: row.get(1)?,
                msg: row.get(2)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// 删除已超过 TTL 的消息，返回删除行数。
    pub(crate) async fn purge_expired(&self, now_ms: u64) -> Result<usize> {
        if self.ttl_secs == 0 {
            return Ok(0);
        }
        let cutoff = now_ms.saturating_sub(self.ttl_secs * 1000);
        let conn = self.conn.lock().await;
        let deleted = conn.execute(
            "DELETE FROM messages WHERE time < ?1",
            params![cutoff as i64],
        )?;
        Ok(deleted)
    }

    /// 删除对应 msg_id（仅限该接收方的队列），返回删除行数。由网格 `sync_ack`
    /// 触发（fetch 取回即删 / 节点间删除同步）；返回 0 表示本节点本就没有
    /// 这些消息（幂等，无需再转发，切断环路）。
    pub(crate) async fn ack(&self, recipient: &str, ids: &[String]) -> Result<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let conn = self.conn.lock().await;
        let placeholders = vec!["?"; ids.len()].join(",");
        let sql =
            format!("DELETE FROM messages WHERE to_peer_id = ?1 AND msg_id IN ({placeholders})");
        let mut stmt = conn.prepare(&sql)?;
        stmt.raw_bind_parameter(1, recipient)?;
        for (i, id) in ids.iter().enumerate() {
            stmt.raw_bind_parameter(i + 2, id)?;
        }
        let deleted = stmt.raw_execute()?;
        Ok(deleted)
    }
}
