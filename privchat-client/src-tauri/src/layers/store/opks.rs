//! 一次性预密钥（OPK）：生成、取用、按 id 查询、用完即删。
//!
//! OPK 只服务「对方发起会话」那一次：发起方在邀请里拿到公钥，响应方
//! 收到首条消息后按 header 里的 id 取私钥派生 root₀，派生完立刻删除。

use super::*;
use rusqlite::OptionalExtension;

impl Store {
    /// 追加一把一次性预密钥，返回其 id。
    pub fn add_opk(&self, local_id: &str, sk: &[u8]) -> Result<u64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO opks (local_id, sk, used) VALUES (?1, ?2, 0)",
            params![local_id, sk],
        )?;
        Ok(conn.last_insert_rowid() as u64)
    }

    /// 取一把未用过的 OPK（标记为已用）。
    pub fn take_opk(&self, local_id: &str) -> Result<Option<(u64, Vec<u8>)>> {
        let conn = self.conn.lock().unwrap();
        let row: Option<(i64, Vec<u8>)> = conn
            .query_row(
                "SELECT id, sk FROM opks WHERE local_id = ?1 AND used = 0 ORDER BY id LIMIT 1",
                params![local_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((id, sk)) = row else { return Ok(None) };
        conn.execute("UPDATE opks SET used = 1 WHERE id = ?1", params![id])?;
        Ok(Some((id as u64, sk)))
    }

    /// 按 id 取未用过的 OPK 私钥（响应方解首条消息用）。
    pub fn opk_by_id(&self, local_id: &str, id: u64) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.lock().unwrap();
        let row: Option<Vec<u8>> = conn
            .query_row(
                "SELECT sk FROM opks WHERE id = ?1 AND local_id = ?2 AND used = 0",
                params![id as i64, local_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(row)
    }

    /// 用掉后删除。
    pub fn delete_opk(&self, id: u64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM opks WHERE id = ?1", params![id as i64])?;
        Ok(())
    }

    /// 清点某身份还有多少未用 OPK。
    pub fn count_unused_opks(&self, local_id: &str) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let n: i64 = conn.query_row(
            "SELECT count(*) FROM opks WHERE local_id = ?1 AND used = 0",
            params![local_id],
            |row| row.get(0),
        )?;
        Ok(n as usize)
    }

    /// 列出未用 OPK 的 id 与私钥（发布邀请时用）。
    pub fn list_opks(&self, local_id: &str, limit: usize) -> Result<Vec<(u64, Vec<u8>)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, sk FROM opks WHERE local_id = ?1 AND used = 0 ORDER BY id LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![local_id, limit as i64], |row| {
            Ok((row.get::<_, i64>(0)? as u64, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}
