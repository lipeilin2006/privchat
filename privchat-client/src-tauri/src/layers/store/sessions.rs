//! 会话表：一个联系人可有多段会话（并发发起时保留只读段）。

use super::*;

impl Store {
    /// 覆盖某个联系人的全部会话（先删后插）。
    /// `rows`：`(session_id, role, active, ratchet_state)`。
    pub fn save_sessions(
        &self,
        local_id: &str,
        peer_id: &str,
        rows: &[(String, String, bool, Vec<u8>)],
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM sessions WHERE local_id = ?1 AND peer_id = ?2",
            params![local_id, peer_id],
        )?;
        let mut stmt = conn.prepare(
            "INSERT OR REPLACE INTO sessions (session_id, local_id, peer_id, role, active, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        for (sid, role, active, state) in rows {
            stmt.execute(params![sid, local_id, peer_id, role, *active as i64, state])?;
        }
        Ok(())
    }
    /// 读取全部会话：`(session_id, local_id, peer_id, role, active, state)`。
    pub fn load_sessions(&self) -> Result<Vec<(String, String, String, String, bool, Vec<u8>)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT session_id, local_id, peer_id, role, active, state FROM sessions")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)? != 0,
                row.get::<_, Vec<u8>>(5)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
    /// 删除某专属身份下的全部会话（删除联系人时调用）。
    pub fn delete_sessions(&self, local_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM sessions WHERE local_id = ?1",
            params![local_id],
        )?;
        Ok(())
    }
}
