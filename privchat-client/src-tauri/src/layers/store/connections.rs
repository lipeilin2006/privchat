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
    /// "owner" / "joiner"。
    pub role: String,
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
    pub last_used: u64,
}

impl Store {
    /// 写入/覆盖一条连接。
    pub fn save_connection(&self, row: &ConnRow) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO connections
             (conn_id, name, role, state, in_queue, in_mailbox, out_queue, out_mailbox,
              out_sender_sk, owner_sk, e2e_state, created, last_used)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                row.conn_id,
                row.name,
                row.role,
                row.state,
                row.in_queue,
                row.in_mailbox,
                row.out_queue,
                row.out_mailbox,
                row.out_sender_sk,
                row.owner_sk,
                row.e2e_state,
                row.created as i64,
                row.last_used as i64,
            ],
        )?;
        Ok(())
    }

    /// 读取全部连接。
    pub fn load_connections(&self) -> Result<Vec<ConnRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT conn_id, name, role, state, in_queue, in_mailbox, out_queue, out_mailbox,
                    out_sender_sk, owner_sk, e2e_state, created, last_used
             FROM connections ORDER BY created",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ConnRow {
                conn_id: row.get(0)?,
                name: row.get(1)?,
                role: row.get(2)?,
                state: row.get(3)?,
                in_queue: row.get(4)?,
                in_mailbox: row.get(5)?,
                out_queue: row.get(6)?,
                out_mailbox: row.get(7)?,
                out_sender_sk: row.get(8)?,
                owner_sk: row.get(9)?,
                e2e_state: row.get(10)?,
                created: row.get::<_, i64>(11)? as u64,
                last_used: row.get::<_, i64>(12)? as u64,
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
                "SELECT conn_id, name, role, state, in_queue, in_mailbox, out_queue, out_mailbox,
                        out_sender_sk, owner_sk, e2e_state, created, last_used
                 FROM connections WHERE conn_id = ?1",
                params![conn_id],
                |row| {
                    Ok(ConnRow {
                        conn_id: row.get(0)?,
                        name: row.get(1)?,
                        role: row.get(2)?,
                        state: row.get(3)?,
                        in_queue: row.get(4)?,
                        in_mailbox: row.get(5)?,
                        out_queue: row.get(6)?,
                        out_mailbox: row.get(7)?,
                        out_sender_sk: row.get(8)?,
                        owner_sk: row.get(9)?,
                        e2e_state: row.get(10)?,
                        created: row.get::<_, i64>(11)? as u64,
                        last_used: row.get::<_, i64>(12)? as u64,
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

/// 连接里的一条消息。
#[derive(Debug, Clone)]
pub struct ConnMessage {
    pub conn_id: String,
    pub msg_id: String,
    /// "me" / "peer"
    pub sender: String,
    pub text: String,
    pub time: u64,
}

impl Store {
    /// 追加一条连接消息（按 msg_id 幂等）。
    pub fn append_conn_message(&self, m: &ConnMessage) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO conn_messages (conn_id, msg_id, sender, text, time)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![m.conn_id, m.msg_id, m.sender, m.text, m.time as i64],
        )?;
        Ok(())
    }

    /// 读某连接的消息（按时间升序）。
    pub fn conn_messages(&self, conn_id: &str, limit: usize) -> Result<Vec<ConnMessage>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT conn_id, msg_id, sender, text, time FROM conn_messages
             WHERE conn_id = ?1 ORDER BY time, rowid LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![conn_id, limit as i64], |row| {
            Ok(ConnMessage {
                conn_id: row.get(0)?,
                msg_id: row.get(1)?,
                sender: row.get(2)?,
                text: row.get(3)?,
                time: row.get::<_, i64>(4)? as u64,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}
