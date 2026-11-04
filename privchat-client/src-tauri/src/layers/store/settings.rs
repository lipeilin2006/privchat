//! 设置项：mailbox 节点、写入副本数、洋葱配置、自动锁定。

use super::*;

const MAILBOX_WRITE_COUNT_KEY: &str = "mailbox_write_count";
const AUTO_LOCK_MINUTES_KEY: &str = "auto_lock_minutes";
const ONION_CONFIG_KEY: &str = "onion_config";

impl Store {
    /// 读取一个应用级设置（键值对）。
    pub(crate) fn load_setting(&self, key: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT value FROM settings WHERE key = ?1")?;
        let mut rows = stmt.query(params![key])?;
        match rows.next()? {
            Some(row) => Ok(Some(row.get(0)?)),
            None => Ok(None),
        }
    }
    /// 写入一个应用级设置（UPSERT）。
    pub(crate) fn save_setting(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }
    /// 读取「每条消息最多成功推送节点数」（0 = 全部已配置节点）。
    /// 默认 3：PEX 会把邻居表自动扩到 64，默认全量写会放大网络开销。
    pub fn load_mailbox_write_count(&self) -> Result<usize> {
        Ok(self
            .load_setting(MAILBOX_WRITE_COUNT_KEY)?
            .and_then(|v| v.parse().ok())
            .filter(|count| *count <= MAX_MAILBOX_WRITE_COUNT)
            .unwrap_or(3))
    }
    /// 保存 mailbox 投放数量（0 = 全部已配置节点）。
    pub fn save_mailbox_write_count(&self, count: usize) -> Result<()> {
        if count > MAX_MAILBOX_WRITE_COUNT {
            return Err(anyhow!(
                "mailbox write count must be <= {MAX_MAILBOX_WRITE_COUNT}"
            ));
        }
        self.save_setting(MAILBOX_WRITE_COUNT_KEY, &count.to_string())
    }
    /// 洋葱路由配置（JSON：`{"enabled":bool,"relays":[peer_id,...]}`）。
    pub fn load_onion_config(&self) -> Result<String> {
        Ok(self
            .load_setting(ONION_CONFIG_KEY)?
            .unwrap_or_else(|| "{\"enabled\":false,\"relays\":[]}".to_string()))
    }
    pub fn save_onion_config(&self, json: &str) -> Result<()> {
        self.save_setting(ONION_CONFIG_KEY, json)
    }
    pub fn load_auto_lock_minutes(&self) -> Result<u64> {
        Ok(self
            .load_setting(AUTO_LOCK_MINUTES_KEY)?
            .and_then(|value| value.parse().ok())
            .unwrap_or(0))
    }
    pub fn save_auto_lock_minutes(&self, minutes: u64) -> Result<()> {
        if !matches!(minutes, 0 | 1 | 5) {
            return Err(anyhow!("unsupported auto lock interval"));
        }
        self.save_setting(AUTO_LOCK_MINUTES_KEY, &minutes.to_string())
    }
    /// mailbox 节点列表。
    pub fn load_mailbox_peers(&self) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT peer_id FROM mailbox_peers")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
    /// 写回 mailbox 节点列表（先删后插）。
    pub fn save_mailbox_peers(&self, peers: &[String]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM mailbox_peers", [])?;
        let mut stmt = conn.prepare("INSERT INTO mailbox_peers (peer_id) VALUES (?1)")?;
        for p in peers {
            stmt.execute(params![p])?;
        }
        Ok(())
    }
}
