//! 设置项：mailbox 节点、洋葱配置、自动锁定。

use super::*;

/// 一个信箱节点：peer_id + 优先级（数字大的先用）。
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MailboxPeer {
    pub peer_id: String,
    pub priority: i64,
}

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
    pub fn load_mailbox_peers(&self) -> Result<Vec<MailboxPeer>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT peer_id, priority FROM mailbox_peers ORDER BY priority DESC, peer_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(MailboxPeer {
                peer_id: row.get(0)?,
                priority: row.get(1)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// 写回信箱节点列表（先删后插）。
    pub fn save_mailbox_peers(&self, peers: &[MailboxPeer]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM mailbox_peers", [])?;
        let mut stmt =
            conn.prepare("INSERT INTO mailbox_peers (peer_id, priority) VALUES (?1, ?2)")?;
        for peer in peers {
            stmt.execute(params![peer.peer_id, peer.priority])?;
        }
        Ok(())
    }
}
