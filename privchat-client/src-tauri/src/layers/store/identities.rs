//! 专属身份：私钥与未绑定身份的过期清理。

use super::*;

const IDENTITY_CREATED_PREFIX: &str = "identity_created:";

impl Store {
    /// 保存一个专属身份的私钥（SecretKey 字节）。整库已加密，直接存 BLOB。
    pub fn save_identity(&self, local_id: &str, secret: &[u8], created_at: u64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO identities (local_id, secret) VALUES (?1, ?2)",
            params![local_id, secret],
        )?;
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![
                format!("{IDENTITY_CREATED_PREFIX}{local_id}"),
                created_at.to_string()
            ],
        )?;
        Ok(())
    }

    /// 读取全部专属身份私钥（local_id → SecretKey 字节）。
    pub fn load_identities(&self) -> Result<HashMap<String, Vec<u8>>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT local_id, secret FROM identities")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut out = HashMap::new();
        for r in rows {
            let (local_id, secret) = r?;
            out.insert(local_id, secret);
        }
        Ok(out)
    }
    /// 删除一个专属身份私钥（删除联系人时调用）。
    pub fn delete_identity(&self, local_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM identities WHERE local_id = ?1",
            params![local_id],
        )?;
        conn.execute(
            "DELETE FROM settings WHERE key = ?1",
            params![format!("{IDENTITY_CREATED_PREFIX}{local_id}")],
        )?;
        Ok(())
    }
    pub fn delete_expired_unbound_identities(
        &self,
        bound: &std::collections::HashSet<String>,
        cutoff: u64,
    ) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT local_id FROM identities")?;
        let ids = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let mut deleted = Vec::new();
        for id in ids {
            if bound.contains(&id) {
                continue;
            }
            let key = format!("{IDENTITY_CREATED_PREFIX}{id}");
            let created = conn
                .query_row(
                    "SELECT value FROM settings WHERE key = ?1",
                    params![key],
                    |row| row.get::<_, String>(0),
                )
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0);
            if created != 0 && created <= cutoff {
                conn.execute("DELETE FROM identities WHERE local_id = ?1", params![id])?;
                conn.execute("DELETE FROM settings WHERE key = ?1", params![key])?;
                deleted.push(id);
            }
        }
        Ok(deleted)
    }
}
