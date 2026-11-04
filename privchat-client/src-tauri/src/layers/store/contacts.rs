//! 联系人表：整表读写（数据量小，直接全量覆盖）。

use super::*;

impl Store {
    /// 联系人表整表读入内存（peer_id → Contact）。
    pub fn load_contacts(&self) -> Result<HashMap<String, Contact>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT peer_id, local_id, name, ticket, peer_spk FROM contacts")?;
        let rows = stmt.query_map([], |row| {
            Ok(Contact {
                peer_id: row.get(0)?,
                local_id: row.get(1)?,
                name: row.get(2)?,
                ticket: row.get(3)?,
                peer_spk: row.get(4)?,
            })
        })?;
        let mut out = HashMap::new();
        for r in rows {
            let c = r?;
            out.insert(c.peer_id.clone(), c);
        }
        Ok(out)
    }
    /// 整表写回联系人（先删后插，数据量小，保证与内存态一致）。
    pub fn save_contacts(&self, contacts: &HashMap<String, Contact>) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM contacts", [])?;
        let mut stmt = conn.prepare(
            "INSERT INTO contacts (peer_id, local_id, name, ticket, peer_spk)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for c in contacts.values() {
            stmt.execute(params![c.peer_id, c.local_id, c.name, c.ticket, c.peer_spk])?;
        }
        Ok(())
    }
}
