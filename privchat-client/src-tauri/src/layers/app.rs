//! L4 应用门面：连接（两条单向队列）+ 设置。
//!
//! 这里没有「联系人」实体：`connections` 表存的就是连接本身，
//! 备注名只是本端显示用的别名。

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::sync::{watch, Mutex};

use super::connection::LinkState;
use super::links::{IrohQueues, LinkManager};
use super::store::{ConnMessage, Store};
use super::transport::Transport;

/// 洋葱路由配置。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OnionConfig {
    pub enabled: bool,
    pub relays: Vec<String>,
}

impl Default for OnionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            relays: Vec::new(),
        }
    }
}

/// L4 应用门面。
#[derive(Clone)]
pub struct App {
    transport: Transport,
    store: Arc<Store>,
    links: Arc<LinkManager>,
    /// 配置的 mailbox 节点（建连接时用第一个）。
    mailbox_peers: Arc<Mutex<Vec<String>>>,
    /// 每条离线消息写入的 mailbox 节点数（保留设置项）。
    mailbox_write_count: Arc<AtomicUsize>,
    onion: Arc<Mutex<OnionConfig>>,
    stop_tx: watch::Sender<bool>,
}

impl App {
    pub async fn start(data_dir: PathBuf, key: [u8; 32]) -> Result<Self> {
        Self::start_inner(data_dir, true, key).await
    }

    pub async fn start_no_relay(data_dir: PathBuf, key: [u8; 32]) -> Result<Self> {
        Self::start_inner(data_dir, false, key).await
    }

    async fn start_inner(data_dir: PathBuf, use_relay: bool, key: [u8; 32]) -> Result<Self> {
        let store = Arc::new(Store::open(&data_dir, key)?);
        let (transport, _rx) = if use_relay {
            Transport::start(store.clone()).await?
        } else {
            Transport::start_no_relay(store.clone()).await?
        };

        let mailbox_peers = Arc::new(Mutex::new(store.load_mailbox_peers().unwrap_or_default()));

        let queue_api = Arc::new(IrohQueues::new(transport.clone()));
        let links = Arc::new(LinkManager::load(store.clone(), queue_api).await?);
        links.set_pool(mailbox_peers.lock().await.clone()).await;
        let mailbox_write_count = Arc::new(AtomicUsize::new(
            store.load_mailbox_write_count().unwrap_or(0),
        ));
        let onion = Arc::new(Mutex::new(
            store
                .load_onion_config()
                .ok()
                .and_then(|json| serde_json::from_str::<OnionConfig>(&json).ok())
                .unwrap_or_default(),
        ));
        let (stop_tx, _) = watch::channel(false);
        Ok(Self {
            transport,
            store,
            links,
            mailbox_peers,
            mailbox_write_count,
            onion,
            stop_tx,
        })
    }

    // ---- 连接 ----

    /// 生成邀请：在 mailbox 上建接收队列，返回 `(conn_id, 邀请串)`。
    pub async fn create_connection(&self, mailbox: &str) -> Result<(String, String)> {
        self.links.create(mailbox).await
    }

    /// 互扫到对方邀请后配对。
    pub async fn accept_connection(&self, conn_id: &str, invite: &str) -> Result<()> {
        self.links.accept(conn_id, invite).await
    }

    /// 在连接上发一条文本（入库）。
    pub async fn send_on_connection(&self, conn_id: &str, text: &str) -> Result<()> {
        self.links.send(conn_id, text.as_bytes()).await?;
        let time = now_ms();
        let _ = self.store.append_conn_message(&ConnMessage {
            conn_id: conn_id.to_string(),
            msg_id: format!("me-{time}"),
            sender: "me".into(),
            text: text.to_string(),
            time,
        });
        Ok(())
    }

    /// 取走并解密该连接的全部待收消息（入库后返回文本）。
    pub async fn poll_connection(&self, conn_id: &str) -> Result<Vec<String>> {
        let blobs = self.links.poll(conn_id).await?;
        let mut out = Vec::new();
        for (i, blob) in blobs.into_iter().enumerate() {
            let text = String::from_utf8_lossy(&blob).into_owned();
            let time = now_ms() + i as u64;
            let _ = self.store.append_conn_message(&ConnMessage {
                conn_id: conn_id.to_string(),
                msg_id: format!("peer-{time}"),
                sender: "peer".into(),
                text: text.clone(),
                time,
            });
            out.push(text);
        }
        Ok(out)
    }

    pub fn connection_history(&self, conn_id: &str) -> Result<Vec<ConnMessage>> {
        self.store.conn_messages(conn_id, 500)
    }

    /// 轮询全部已建立连接（后台任务用）。
    pub async fn poll_all_connections(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for (conn_id, _, state) in self.links.list().await {
            if state != LinkState::Established {
                continue;
            }
            match self.poll_connection(&conn_id).await {
                Ok(texts) => {
                    for text in texts {
                        out.push((conn_id.clone(), text));
                    }
                }
                Err(e) => eprintln!("[app] poll {conn_id} failed: {e}"),
            }
        }
        out
    }

    pub async fn list_connections(&self) -> Vec<(String, Option<String>, LinkState)> {
        self.links.list().await
    }

    pub fn rename_connection(&self, conn_id: &str, name: Option<&str>) -> Result<()> {
        self.links.rename(conn_id, name)
    }

    // ---- 设置 ----

    pub async fn get_onion_config(&self) -> OnionConfig {
        self.onion.lock().await.clone()
    }

    pub async fn set_onion_config(&self, config: OnionConfig) -> Result<()> {
        let json = serde_json::to_string(&config)?;
        self.store.save_onion_config(&json)?;
        *self.onion.lock().await = config;
        Ok(())
    }

    pub async fn get_mailbox_peers(&self) -> Vec<String> {
        self.mailbox_peers.lock().await.clone()
    }

    pub async fn add_mailbox_peer(&self, peer_id: &str) -> Result<()> {
        if peer_id.len() != 64 || !peer_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(anyhow!("mailbox peer id must be 64 hex chars"));
        }
        let mut peers = self.mailbox_peers.lock().await;
        if !peers.iter().any(|p| p == peer_id) {
            peers.push(peer_id.to_string());
            self.store.save_mailbox_peers(&peers)?;
        }
        Ok(())
    }

    pub async fn remove_mailbox_peer(&self, peer_id: &str) -> Result<()> {
        let mut peers = self.mailbox_peers.lock().await;
        peers.retain(|p| p != peer_id);
        self.store.save_mailbox_peers(&peers)?;
        Ok(())
    }

    pub async fn ping_mailbox(&self, peer_id: &str) -> Result<u64> {
        let local_id = self.transport.create_identity().await?;
        let endpoint = self.transport.endpoint_for(&local_id).await?;
        let started = std::time::Instant::now();
        super::mailbox::MailboxClient::ping(&endpoint, peer_id).await?;
        Ok(started.elapsed().as_millis() as u64)
    }

    pub async fn get_mailbox_write_count(&self) -> usize {
        self.mailbox_write_count.load(Ordering::Relaxed)
    }

    pub async fn set_mailbox_write_count(&self, count: usize) -> Result<()> {
        self.mailbox_write_count.store(count, Ordering::Relaxed);
        self.store.save_mailbox_write_count(count)
    }

    pub fn get_auto_lock_minutes(&self) -> Result<u64> {
        self.store.load_auto_lock_minutes()
    }

    pub fn set_auto_lock_minutes(&self, minutes: u64) -> Result<()> {
        self.store.save_auto_lock_minutes(minutes)
    }

    // ---- 生命周期 ----

    pub async fn shutdown(&self) {
        let _ = self.stop_tx.send(true);
    }

    pub async fn close(&self) {
        self.transport.close().await;
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
