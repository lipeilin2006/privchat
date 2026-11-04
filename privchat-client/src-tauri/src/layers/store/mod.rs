//! Layer 0.5 · 本地持久化 (SQLite + SQLCipher 全库加密)
//!
//! 整个数据库文件由 SQLCipher 加密（AES-256，页级加密，表结构、行数、
//! 索引全部密文），文件头为随机 salt，不暴露 SQLite 结构信息。
//! 加密密钥 = 密码经 PBKDF2 派生主密钥后，再经 HKDF-Expand 域分离得到的
//! `db_key`（见 vault.rs），通过 `PRAGMA key = "x'<hex>'"` 传入（raw key，
//! 不经 SQLCipher 二次 KDF）。
//!
//! 应用层在加密库内直接读写明文，由 SQLCipher 负责落盘加密，因此不再
//! 需要字段级加密（此前为逐字段 ChaCha20，已移除）。
//!
//! 结构：
//! ```text
//! contacts      (peer_id PK, local_id, name, ticket)
//! messages      (peer_id, msg_id, sender, text, time)
//! mailbox_peers (peer_id PK)
//! identities    (local_id PK, secret BLOB)
//! ratchets      (local_id, peer_id, state BLOB)  —— 双棘轮会话状态
//! settings      (key PK, value)                  —— 应用级设置（键值对）
//! ```
//!
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use anyhow::{anyhow, Result};
use rusqlite::{params, Connection};

mod connections;
mod identities;
mod settings;

pub use connections::{ConnMessage, ConnRow};

/// 每条离线消息写入的 mailbox 节点数（0 = 全部已配置节点）。
pub const UNBOUND_IDENTITY_TTL_MS: u64 = 24 * 60 * 60 * 1000;
pub const MAX_MAILBOX_WRITE_COUNT: usize = 64;

/// SQLite 持久化门面。连接用 `Mutex` 包裹以保证线程安全，且所有操作
/// 都很小（几十到几百行），同步执行即可。
pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    /// 打开（或创建）当前版本的 SQLCipher 加密数据库。
    pub fn open(data_dir: &Path, key: [u8; 32]) -> Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let db_path = data_dir.join("privchat.db");
        let conn = Self::open_with_key(&db_path, &key)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS mailbox_peers (
                 peer_id TEXT PRIMARY KEY
             );
             CREATE TABLE IF NOT EXISTS identities (
                 local_id TEXT PRIMARY KEY,
                 secret BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS connections (
                 conn_id TEXT PRIMARY KEY,
                 name TEXT,
                 role TEXT NOT NULL,
                 state TEXT NOT NULL,
                 in_queue TEXT NOT NULL,
                 in_mailbox TEXT NOT NULL,
                 out_queue TEXT,
                 out_mailbox TEXT,
                 out_sender_sk BLOB,
                 owner_sk BLOB NOT NULL,
                 e2e_state BLOB NOT NULL,
                 created INTEGER NOT NULL,
                 last_used INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS conn_messages (
                 conn_id TEXT NOT NULL,
                 msg_id TEXT NOT NULL,
                 sender TEXT NOT NULL,
                 text TEXT NOT NULL,
                 time INTEGER NOT NULL,
                 PRIMARY KEY (conn_id, msg_id)
             );
                 CREATE TABLE IF NOT EXISTS settings (
                     key TEXT PRIMARY KEY,
                     value TEXT NOT NULL
                 );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// 以派生密钥打开加密库。`PRAGMA key` 必须是连接后的首个操作。
    /// 密钥错误或数据库不是当前加密库时直接返回错误。
    fn open_with_key(db_path: &Path, key: &[u8; 32]) -> Result<Connection> {
        let conn = Connection::open(db_path)?;
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        conn.execute_batch(&format!("PRAGMA key = \"x'{hex}'\";"))?;
        // 触发首页读取：密钥错误或非加密库会在此报错。
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
            r.get::<_, i64>(0)
        })
        .map_err(|e| anyhow!("cannot open database with key: {e}"))?;
        Ok(conn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x42; 32];
    const WRONG_KEY: [u8; 32] = [0x99; 32];

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("privchat-store-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn sqlite_roundtrip_encrypted_file() {
        let dir = temp_dir("enc");
        let store = Store::open(&dir, KEY).expect("open");
        assert!(dir.join("privchat.db").exists());

        store
            .save_mailbox_peers(&["mb1".to_string(), "mb2".to_string()])
            .expect("save mailbox");
        assert_eq!(store.load_mailbox_peers().unwrap(), vec!["mb1", "mb2"]);

        // 落盘文件不得含明文。
        let raw = std::fs::read(dir.join("privchat.db")).unwrap();
        assert!(
            !raw.windows(8).any(|w| w == b"mailbox-"),
            "plaintext must not appear in db file"
        );

        drop(store);
        let store2 = Store::open(&dir, KEY).expect("reopen");
        assert_eq!(store2.load_mailbox_peers().unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_key_cannot_open() {
        let dir = temp_dir("wrongkey");
        let store = Store::open(&dir, KEY).expect("open");
        store.save_mailbox_peers(&["mb".to_string()]).expect("save");
        drop(store);

        // 错误密钥打开加密库 → 打开即报错（SQLCipher 首页解密失败）。
        assert!(
            Store::open(&dir, WRONG_KEY).is_err(),
            "wrong key must fail open"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_ok() {
        let dir = temp_dir("empty");
        let store = Store::open(&dir, KEY).expect("open empty");
        assert!(store.load_mailbox_peers().unwrap().is_empty());
        assert!(store.load_connections().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn connections_roundtrip() {
        let dir = temp_dir("connections");
        let store = Store::open(&dir, [7u8; 32]).expect("open");
        let row = ConnRow {
            conn_id: "c1".into(),
            name: Some("Alice".into()),
            role: "owner".into(),
            state: "invited".into(),
            in_queue: "00112233445566778899aabbccddeeff".into(),
            in_mailbox: "mb".into(),
            out_queue: None,
            out_mailbox: None,
            out_sender_sk: None,
            owner_sk: vec![1u8; 32],
            e2e_state: vec![2u8; 8],
            created: 1,
            last_used: 1,
        };
        store.save_connection(&row).expect("save");
        let loaded = store.load_connections().expect("load");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].conn_id, "c1");
        assert_eq!(loaded[0].name.as_deref(), Some("Alice"));

        store.rename_connection("c1", Some("Bob")).expect("rename");
        assert_eq!(
            store.connection("c1").unwrap().unwrap().name.as_deref(),
            Some("Bob")
        );

        store.delete_connection("c1").expect("delete");
        assert!(store.connection("c1").unwrap().is_none());
    }

    #[test]
    fn settings_roundtrip() {
        let dir = temp_dir("settings");
        let store = Store::open(&dir, KEY).expect("open");

        // 未设置时缺省 3（PEX 会扩充邻居表，默认全量写代价过高）。
        assert_eq!(store.load_mailbox_write_count().unwrap(), 3);
        assert!(store.load_setting("nope").unwrap().is_none());

        store.save_mailbox_write_count(2).expect("save count");
        assert_eq!(store.load_mailbox_write_count().unwrap(), 2);
        store.save_setting("theme", "dark").expect("save setting");
        assert_eq!(
            store.load_setting("theme").unwrap().as_deref(),
            Some("dark")
        );

        // UPSERT：同一键覆盖。
        store.save_mailbox_write_count(3).expect("save count 3");
        assert_eq!(store.load_mailbox_write_count().unwrap(), 3);

        // 重开后持久化仍在。
        drop(store);
        let store2 = Store::open(&dir, KEY).expect("reopen");
        assert_eq!(store2.load_mailbox_write_count().unwrap(), 3);
        assert_eq!(
            store2.load_setting("theme").unwrap().as_deref(),
            Some("dark")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn identities_roundtrip_encrypted_file() {
        let dir = temp_dir("idents");
        let store = Store::open(&dir, KEY).expect("open");

        let secret: [u8; 32] = [0x77; 32];
        store
            .save_identity("local1", &secret, 1_000)
            .expect("save identity");
        store
            .save_identity("local2", &[0x11; 32], 2_000)
            .expect("save identity2");

        let loaded = store.load_identities().expect("load identities");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded["local1"].as_slice(), &secret);
        assert_eq!(loaded["local2"].as_slice(), &[0x11; 32]);

        store.delete_identity("local1").expect("delete identity");
        let after = store.load_identities().expect("reload");
        assert_eq!(after.len(), 1);
        assert!(after.contains_key("local2"));

        // 落盘不含明文私钥字节（整库加密）。
        let raw = std::fs::read(dir.join("privchat.db")).unwrap();
        assert!(
            !raw.windows(32).any(|w| w == &secret[..]),
            "plaintext secret must not appear in db file"
        );

        // 重开后持久化仍在。
        drop(store);
        let store2 = Store::open(&dir, KEY).expect("reopen");
        assert_eq!(store2.load_identities().unwrap().len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
