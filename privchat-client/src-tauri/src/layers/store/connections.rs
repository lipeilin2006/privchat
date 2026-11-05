//! 连接表：一条连接 = 两条单向队列 + 一份 E2E 状态。
//!
//! 没有「联系人」这个实体：`name` 只是本端给这条连接起的备注。

use super::*;
use rusqlite::OptionalExtension;

/// 连接记录（持久化形态）。
#[derive(Debug, Clone)]
pub struct ConnRow {
    /// 连接 id（握手完成后 = session_id；之前用随机值）。
    pub conn_id: String,
    /// 本端备注（可空）。
    pub name: Option<String>,
    /// "invited" / "joining" / "established" / "closed"。
    pub state: String,
    /// 本端入站队列。
    pub in_queue: String,
    pub in_mailbox: String,
    /// 对方入站队列（未握手时为空）。
    pub out_queue: Option<String>,
    pub out_mailbox: Option<String>,
    /// 写对方队列用的 sender 私钥。
    pub out_sender_sk: Option<Vec<u8>>,
    /// 本端队列的 owner 私钥（读/删用）。
    pub owner_sk: Vec<u8>,
    /// E2E 会话状态（`Connection::to_bytes`）。
    pub e2e_state: Vec<u8>,
    pub created: u64,
    /// 轮换后还在排空的旧队列（JSON 数组）。
    pub draining: String,
}

impl Store {
    /// 写入/覆盖一条连接。
    pub fn save_connection(&self, row: &ConnRow) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO connections
             (conn_id, name, state, in_queue, in_mailbox, out_queue, out_mailbox,
              out_sender_sk, owner_sk, e2e_state, created, draining)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                row.conn_id,
                row.name,
                row.state,
                row.in_queue,
                row.in_mailbox,
                row.out_queue,
                row.out_mailbox,
                row.out_sender_sk,
                row.owner_sk,
                row.e2e_state,
                row.created as i64,
                row.draining,
            ],
        )?;
        Ok(())
    }

    /// 读取全部连接。
    pub fn load_connections(&self) -> Result<Vec<ConnRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT conn_id, name, state, in_queue, in_mailbox, out_queue, out_mailbox,
                    out_sender_sk, owner_sk, e2e_state, created, draining
             FROM connections ORDER BY created",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ConnRow {
                conn_id: row.get(0)?,
                name: row.get(1)?,
                state: row.get(2)?,
                in_queue: row.get(3)?,
                in_mailbox: row.get(4)?,
                out_queue: row.get(5)?,
                out_mailbox: row.get(6)?,
                out_sender_sk: row.get(7)?,
                owner_sk: row.get(8)?,
                e2e_state: row.get(9)?,
                created: row.get::<_, i64>(10)? as u64,
                draining: row.get(11)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// 按 id 取一条连接。
    pub fn connection(&self, conn_id: &str) -> Result<Option<ConnRow>> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT conn_id, name, state, in_queue, in_mailbox, out_queue, out_mailbox,
                        out_sender_sk, owner_sk, e2e_state, created, draining
                 FROM connections WHERE conn_id = ?1",
                params![conn_id],
                |row| {
                    Ok(ConnRow {
                        conn_id: row.get(0)?,
                        name: row.get(1)?,
                        state: row.get(2)?,
                        in_queue: row.get(3)?,
                        in_mailbox: row.get(4)?,
                        out_queue: row.get(5)?,
                        out_mailbox: row.get(6)?,
                        out_sender_sk: row.get(7)?,
                        owner_sk: row.get(8)?,
                        e2e_state: row.get(9)?,
                        created: row.get::<_, i64>(10)? as u64,
                        draining: row.get(11)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// 删除一条连接。
    pub fn delete_connection(&self, conn_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM connections WHERE conn_id = ?1",
            params![conn_id],
        )?;
        Ok(())
    }

    /// 更新备注名。
    pub fn rename_connection(&self, conn_id: &str, name: Option<&str>) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE connections SET name = ?2 WHERE conn_id = ?1",
            params![conn_id, name],
        )?;
        Ok(())
    }
}

/// 搜索命中。
#[derive(Debug, Clone, serde::Serialize)]
pub struct SearchHit {
    pub conn_id: String,
    pub name: Option<String>,
    pub msg_id: String,
    pub sender: String,
    pub text: String,
    pub time: u64,
    pub kind: String,
}

/// 连接里的一条消息。
#[derive(Debug, Clone)]
pub struct ConnMessage {
    pub conn_id: String,
    pub msg_id: String,
    /// "me" / "peer"
    pub sender: String,
    pub text: String,
    pub time: u64,
    /// "text" / "file"（图片也是 file，看 mime）
    pub kind: String,
    pub name: Option<String>,
    pub mime: Option<String>,
    pub data: Option<Vec<u8>>,
}

impl Store {
    /// 追加一条连接消息（按 msg_id 幂等）。
    pub fn append_conn_message(&self, m: &ConnMessage) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO conn_messages
             (conn_id, msg_id, sender, text, time, kind, name, mime, data)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                m.conn_id,
                m.msg_id,
                m.sender,
                m.text,
                m.time as i64,
                m.kind,
                m.name,
                m.mime,
                m.data
            ],
        )?;
        Ok(())
    }

    /// 取一条消息。
    pub fn message(&self, conn_id: &str, msg_id: &str) -> Result<Option<ConnMessage>> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT conn_id, msg_id, sender, text, time, kind, name, mime, data
                 FROM conn_messages WHERE conn_id = ?1 AND msg_id = ?2",
                params![conn_id, msg_id],
                |row| {
                    Ok(ConnMessage {
                        conn_id: row.get(0)?,
                        msg_id: row.get(1)?,
                        sender: row.get(2)?,
                        text: row.get(3)?,
                        time: row.get::<_, i64>(4)? as u64,
                        kind: row.get(5)?,
                        name: row.get(6)?,
                        mime: row.get(7)?,
                        data: row.get(8)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// 全局搜索消息正文（LIKE，转义通配符）。
    pub fn search_messages(&self, query: &str, limit: usize) -> Result<Vec<SearchHit>> {
        let escaped = query
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let pattern = format!("%{escaped}%");
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT m.conn_id, c.name, m.msg_id, m.sender, m.text, m.time, m.kind
             FROM conn_messages m LEFT JOIN connections c ON c.conn_id = m.conn_id
             WHERE m.text LIKE ?1 ESCAPE '\\'
             ORDER BY m.time DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![pattern, limit as i64], |row| {
            Ok(SearchHit {
                conn_id: row.get(0)?,
                name: row.get(1)?,
                msg_id: row.get(2)?,
                sender: row.get(3)?,
                text: row.get(4)?,
                time: row.get::<_, i64>(5)? as u64,
                kind: row.get(6)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// 读某连接的消息（按时间升序）。
    pub fn conn_messages(&self, conn_id: &str, limit: usize) -> Result<Vec<ConnMessage>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT conn_id, msg_id, sender, text, time, kind, name, mime, data
             FROM conn_messages WHERE conn_id = ?1 ORDER BY time, rowid LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![conn_id, limit as i64], |row| {
            Ok(ConnMessage {
                conn_id: row.get(0)?,
                msg_id: row.get(1)?,
                sender: row.get(2)?,
                text: row.get(3)?,
                time: row.get::<_, i64>(4)? as u64,
                kind: row.get(5)?,
                name: row.get(6)?,
                mime: row.get(7)?,
                data: row.get(8)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}
