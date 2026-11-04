//! 消息历史与草稿。

use super::*;

impl Store {
    /// 消息历史整表读入内存（peer_id → 消息列表，按 time 升序）。
    pub fn load_history(&self) -> Result<HashMap<String, Vec<ChatMessage>>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT peer_id, msg_id, sender, text, time FROM messages")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                ChatMessage {
                    id: row.get(1)?,
                    from: row.get(2)?,
                    text: row.get(3)?,
                    time: row.get::<_, i64>(4)? as u64,
                },
            ))
        })?;
        let mut out: HashMap<String, Vec<ChatMessage>> = HashMap::new();
        for r in rows {
            let (peer_id, msg) = r?;
            out.entry(peer_id).or_default().push(msg);
        }
        for msgs in out.values_mut() {
            msgs.sort_by_key(|m| m.time);
        }
        Ok(out)
    }
    /// 整表写回历史（先删后插，保证幂等去重）。
    pub fn save_history(&self, history: &HashMap<String, Vec<ChatMessage>>) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM messages", [])?;
        let mut stmt = conn.prepare(
            "INSERT INTO messages (peer_id, msg_id, sender, text, time) VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for (peer_id, msgs) in history {
            for m in msgs {
                stmt.execute(params![peer_id, m.id, m.from, m.text, m.time as i64])?;
            }
        }
        Ok(())
    }
    pub fn search_messages(&self, query: &str, limit: usize) -> Result<Vec<(String, ChatMessage)>> {
        let conn = self.conn.lock().unwrap();
        let pattern = format!("%{query}%");
        let mut stmt = conn.prepare(
            "SELECT peer_id, msg_id, sender, text, time FROM messages
             WHERE text LIKE ?1 ORDER BY time DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![pattern, limit as i64], |row| {
            Ok((
                row.get(0)?,
                ChatMessage {
                    id: row.get(1)?,
                    from: row.get(2)?,
                    text: row.get(3)?,
                    time: row.get::<_, i64>(4)? as u64,
                },
            ))
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
    pub fn load_draft(&self, peer_id: &str) -> Result<String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT text FROM drafts WHERE peer_id = ?1",
            params![peer_id],
            |row| row.get(0),
        )
        .or_else(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => Ok(String::new()),
            other => Err(other),
        })
        .map_err(Into::into)
    }
    pub fn save_draft(&self, peer_id: &str, text: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        if text.is_empty() {
            conn.execute("DELETE FROM drafts WHERE peer_id = ?1", params![peer_id])?;
        } else {
            conn.execute(
                "INSERT INTO drafts (peer_id, text) VALUES (?1, ?2)
                 ON CONFLICT(peer_id) DO UPDATE SET text = excluded.text",
                params![peer_id, text],
            )?;
        }
        Ok(())
    }
}
