//! L4 应用门面：连接（两条单向队列）+ 设置。
//!
//! 这里没有「联系人」实体：`connections` 表存的就是连接本身，
//! 备注名只是本端显示用的别名。

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::sync::{watch, Mutex};

use super::connection::LinkState;
use super::links::{IrohQueues, LinkManager};
use super::store::{ConnMessage, MailboxPeer, Store};
use super::transport::Transport;

/// 一次测速的结果。
#[derive(Debug, Clone, serde::Serialize)]
pub struct MailboxPing {
    pub peer_id: String,
    /// 成功的往返毫秒数；失败为 None。
    pub ms: Option<u64>,
    pub error: Option<String>,
}

impl MailboxPing {
    fn failed(peer_id: &str, error: &str) -> Self {
        Self {
            peer_id: peer_id.to_string(),
            ms: None,
            error: Some(error.to_string()),
        }
    }
}

/// 优先级的合法区间：0..=9，数字越大越先用。
fn clamp_priority(priority: i64) -> i64 {
    priority.clamp(0, 9)
}

fn peer_ids(peers: &[MailboxPeer]) -> Vec<String> {
    peers.iter().map(|p| p.peer_id.clone()).collect()
}

/// 选信箱：优先级最高的那一档里，挑实测延迟最低的；
/// 都没测过就按列表顺序（列表本身已按优先级排序）。
fn choose_peer(
    peers: &[MailboxPeer],
    latencies: &std::collections::HashMap<String, u64>,
) -> Option<String> {
    let top = peers.iter().map(|p| p.priority).max()?;
    peers
        .iter()
        .filter(|p| p.priority == top)
        .min_by_key(|p| latencies.get(&p.peer_id).copied().unwrap_or(u64::MAX))
        .map(|p| p.peer_id.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: &str, priority: i64) -> MailboxPeer {
        MailboxPeer {
            peer_id: id.to_string(),
            priority,
        }
    }

    #[test]
    fn picks_highest_priority_first() {
        let peers = vec![peer("hi", 5), peer("lo", 0)];
        let mut latencies = std::collections::HashMap::new();
        latencies.insert("lo".to_string(), 5);
        latencies.insert("hi".to_string(), 300);
        assert_eq!(choose_peer(&peers, &latencies).as_deref(), Some("hi"));
    }

    #[test]
    fn ties_pick_lowest_latency() {
        let peers = vec![peer("a", 3), peer("b", 3), peer("c", 1)];
        let mut latencies = std::collections::HashMap::new();
        latencies.insert("a".to_string(), 120);
        latencies.insert("b".to_string(), 40);
        assert_eq!(choose_peer(&peers, &latencies).as_deref(), Some("b"));
    }

    #[test]
    fn untested_nodes_are_last_resort() {
        let peers = vec![peer("slow", 3), peer("untested", 3)];
        let mut latencies = std::collections::HashMap::new();
        latencies.insert("slow".to_string(), 900);
        assert_eq!(choose_peer(&peers, &latencies).as_deref(), Some("slow"));
        assert_eq!(
            choose_peer(&peers, &std::collections::HashMap::new()).as_deref(),
            Some("slow"),
            "no latencies -> first in list"
        );
    }
}

/// 洋葱路由配置。
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct OnionConfig {
    pub enabled: bool,
    pub relays: Vec<String>,
}

/// L4 应用门面。
#[derive(Clone)]
pub struct App {
    transport: Transport,
    store: Arc<Store>,
    links: Arc<LinkManager>,
    /// 配置的信箱节点（带优先级；建连接时按优先级 + 延迟挑一台）。
    mailbox_peers: Arc<Mutex<Vec<MailboxPeer>>>,
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
        let transport = if use_relay {
            Transport::start(store.clone()).await?
        } else {
            Transport::start_no_relay(store.clone()).await?
        };

        let mailbox_peers = Arc::new(Mutex::new(store.load_mailbox_peers().unwrap_or_default()));

        let onion = Arc::new(Mutex::new(
            store
                .load_onion_config()
                .ok()
                .and_then(|json| serde_json::from_str::<OnionConfig>(&json).ok())
                .unwrap_or_default(),
        ));
        let queue_api = Arc::new(IrohQueues::new(transport.clone(), onion.clone()));
        let links = Arc::new(LinkManager::load(store.clone(), queue_api).await?);
        links
            .set_pool(peer_ids(&mailbox_peers.lock().await.clone()))
            .await;
        let (stop_tx, _) = watch::channel(false);
        Ok(Self {
            transport,
            store,
            links,
            mailbox_peers,
            onion,
            stop_tx,
        })
    }

    // ---- 连接 ----

    /// 生成邀请：在信箱上建接收队列，返回 `(conn_id, 邀请串)`。
    ///
    /// 不指定信箱时按「优先级最高 → 同优先级里延迟最低」自动挑一台。
    pub async fn create_connection(&self, mailbox: Option<&str>) -> Result<(String, String)> {
        let mailbox = match mailbox.map(str::trim).filter(|m| !m.is_empty()) {
            Some(mailbox) => mailbox.to_string(),
            None => self.pick_mailbox().await?,
        };
        self.links.create(&mailbox).await
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
            msg_id: next_msg_id("me", time),
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
                msg_id: next_msg_id("peer", time),
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

    pub async fn get_mailbox_peers(&self) -> Vec<MailboxPeer> {
        self.mailbox_peers.lock().await.clone()
    }

    pub async fn add_mailbox_peer(&self, peer_id: &str, priority: i64) -> Result<()> {
        let peer_id = peer_id.trim();
        if peer_id.len() != 64 || !peer_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(anyhow!("mailbox peer id must be 64 hex chars"));
        }
        let mut peers = self.mailbox_peers.lock().await;
        match peers.iter_mut().find(|p| p.peer_id == peer_id) {
            Some(peer) => peer.priority = clamp_priority(priority),
            None => peers.push(MailboxPeer {
                peer_id: peer_id.to_string(),
                priority: clamp_priority(priority),
            }),
        }
        peers.sort_by(|a, b| b.priority.cmp(&a.priority).then(a.peer_id.cmp(&b.peer_id)));
        self.store.save_mailbox_peers(&peers)?;
        self.links.set_pool(peer_ids(&peers)).await;
        Ok(())
    }

    pub async fn set_mailbox_priority(&self, peer_id: &str, priority: i64) -> Result<()> {
        let mut peers = self.mailbox_peers.lock().await;
        let Some(peer) = peers.iter_mut().find(|p| p.peer_id == peer_id) else {
            return Err(anyhow!("unknown mailbox peer"));
        };
        peer.priority = clamp_priority(priority);
        peers.sort_by(|a, b| b.priority.cmp(&a.priority).then(a.peer_id.cmp(&b.peer_id)));
        self.store.save_mailbox_peers(&peers)?;
        self.links.set_pool(peer_ids(&peers)).await;
        Ok(())
    }

    pub async fn remove_mailbox_peer(&self, peer_id: &str) -> Result<()> {
        let mut peers = self.mailbox_peers.lock().await;
        peers.retain(|p| p.peer_id != peer_id);
        self.store.save_mailbox_peers(&peers)?;
        self.links.set_pool(peer_ids(&peers)).await;
        Ok(())
    }

    /// 测速：一次临时身份，并发测所有给定节点（省得每台各建一条连接）。
    pub async fn ping_mailboxes(&self, peers: &[String]) -> Vec<MailboxPing> {
        if peers.is_empty() {
            return Vec::new();
        }
        let Ok(local_id) = self.transport.create_identity().await else {
            return peers
                .iter()
                .map(|peer| MailboxPing::failed(peer, "创建拨号身份失败"))
                .collect();
        };
        let endpoint = match self.transport.endpoint_for(&local_id).await {
            Ok(endpoint) => endpoint,
            Err(e) => {
                self.transport.forget(&local_id).await;
                return peers
                    .iter()
                    .map(|peer| MailboxPing::failed(peer, &e.to_string()))
                    .collect();
            }
        };

        let mut set = tokio::task::JoinSet::new();
        for peer in peers {
            let endpoint = endpoint.clone();
            let peer = peer.clone();
            set.spawn(async move {
                let started = std::time::Instant::now();
                match super::mailbox::MailboxClient::ping(&endpoint, &peer).await {
                    Ok(()) => MailboxPing {
                        peer_id: peer,
                        ms: Some(started.elapsed().as_millis() as u64),
                        error: None,
                    },
                    Err(e) => MailboxPing {
                        peer_id: peer,
                        ms: None,
                        error: Some(e.to_string()),
                    },
                }
            });
        }
        let mut out = Vec::new();
        while let Some(res) = set.join_next().await {
            if let Ok(ping) = res {
                out.push(ping);
            }
        }
        self.transport.forget(&local_id).await;
        out
    }

    pub async fn ping_mailbox(&self, peer_id: &str) -> Result<u64> {
        let pings = self.ping_mailboxes(&[peer_id.to_string()]).await;
        match pings.into_iter().next() {
            Some(MailboxPing { ms: Some(ms), .. }) => Ok(ms),
            Some(MailboxPing { error: Some(e), .. }) => Err(anyhow!(e)),
            Some(MailboxPing { error: None, .. }) => Err(anyhow!("ping failed")),
            None => Err(anyhow!("ping failed")),
        }
    }

    /// 挑一台信箱建队列：先看优先级，最高的一档里挑延迟最低的。
    pub async fn pick_mailbox(&self) -> Result<String> {
        let peers = self.mailbox_peers.lock().await.clone();
        if peers.is_empty() {
            return Err(anyhow!("还没有配置信箱节点"));
        }
        let top = peers.iter().map(|p| p.priority).max().unwrap_or(0);
        let candidates: Vec<String> = peers
            .iter()
            .filter(|p| p.priority == top)
            .map(|p| p.peer_id.clone())
            .collect();
        if candidates.len() == 1 {
            return Ok(candidates[0].clone());
        }
        // 同优先级：实测一把，取最快的；全失败就退化成第一台。
        let pings = self.ping_mailboxes(&candidates).await;
        let latencies: std::collections::HashMap<String, u64> = pings
            .into_iter()
            .filter_map(|ping| ping.ms.map(|ms| (ping.peer_id, ms)))
            .collect();
        Ok(choose_peer(&peers, &latencies).unwrap_or_else(|| candidates[0].clone()))
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

/// 同一毫秒连发两条也不会撞主键：时间戳 + 进程内自增。
fn next_msg_id(prefix: &str, time: u64) -> String {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{prefix}-{time}-{seq}")
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
