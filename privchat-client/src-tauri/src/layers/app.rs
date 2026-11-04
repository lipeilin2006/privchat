//! L4 应用门面：连接（两条单向队列）+ 设置。
//!
//! 这里没有「联系人」实体：`connections` 表存的就是连接本身，
//! 备注名只是本端显示用的别名。

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::sync::{watch, Mutex};

use super::connection::LinkState;
use super::links::{IrohQueues, LinkManager};
use super::store::{ConnMessage, MailboxPeer, Store};
use super::transport::Transport;

/// 中继测速结果。
#[derive(Debug, Clone, serde::Serialize)]
pub struct RelayPing {
    pub peer_id: String,
    pub ms: Option<u64>,
    pub error: Option<String>,
}

impl RelayPing {
    fn failed(peer_id: &str, error: &str) -> Self {
        Self {
            peer_id: peer_id.to_string(),
            ms: None,
            error: Some(error.to_string()),
        }
    }
}

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

/// 统一的选点打分：`延迟(ms) * 0.01 * 权重 + 优先级 * (1 - 权重)`。
///
/// 权重 0 = 只看优先级，1 = 只看延迟。分数越低越好。
/// 没测过延迟的节点按 300ms 估（中间值），不至于因为没测速就永远选不上。
pub fn routing_score(priority: i64, latency_ms: Option<u64>, weight: f64) -> f64 {
    let weight = weight.clamp(0.0, 1.0);
    let latency = latency_ms.unwrap_or(300) as f64;
    // 优先级 9 折算成 0 成本、0 折算成 9 —— 和「数值越大越先用」对齐。
    let priority_cost = (9 - priority.clamp(0, 9)) as f64;
    latency * 0.01 * weight + priority_cost * (1.0 - weight)
}

fn clamp_weight(weight: f64) -> f64 {
    if weight.is_finite() {
        weight.clamp(0.0, 1.0)
    } else {
        0.5
    }
}

/// 优先级的合法区间：0..=9，数字越大越先用。
fn clamp_priority(priority: i64) -> i64 {
    priority.clamp(0, 9)
}

fn peer_ids(peers: &[MailboxPeer]) -> Vec<String> {
    peers.iter().map(|p| p.peer_id.clone()).collect()
}

/// 选信箱：和中继用同一套打分（分数最低的赢）。
fn choose_peer(
    peers: &[MailboxPeer],
    latencies: &std::collections::HashMap<String, u64>,
    weight: f64,
) -> Option<String> {
    peers
        .iter()
        .min_by(|a, b| {
            let sa = routing_score(a.priority, latencies.get(&a.peer_id).copied(), weight);
            let sb = routing_score(b.priority, latencies.get(&b.peer_id).copied(), weight);
            sa.partial_cmp(&sb).unwrap_or(std::cmp::Ordering::Equal)
        })
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
    fn weight_zero_follows_priority() {
        let peers = vec![peer("hi", 9), peer("lo", 0)];
        let mut latencies = std::collections::HashMap::new();
        latencies.insert("lo".to_string(), 5);
        latencies.insert("hi".to_string(), 300);
        assert_eq!(
            choose_peer(&peers, &latencies, 0.0).as_deref(),
            Some("hi"),
            "weight 0 = priority only"
        );
    }

    #[test]
    fn weight_one_follows_latency() {
        let peers = vec![peer("slow_hi_prio", 9), peer("fast", 0)];
        let mut latencies = std::collections::HashMap::new();
        latencies.insert("slow_hi_prio".to_string(), 300);
        latencies.insert("fast".to_string(), 20);
        assert_eq!(
            choose_peer(&peers, &latencies, 1.0).as_deref(),
            Some("fast"),
            "weight 1 = latency only"
        );
    }

    #[test]
    fn score_blends_priority_and_latency() {
        // prio 5 / 100ms：100*0.01*0.5 + 4*0.5 = 2.5
        // prio 0 / 50ms ：50*0.01*0.5 + 9*0.5  = 4.75
        let peers = vec![peer("balanced", 5), peer("fast_low_prio", 0)];
        let mut latencies = std::collections::HashMap::new();
        latencies.insert("balanced".to_string(), 100);
        latencies.insert("fast_low_prio".to_string(), 50);
        assert_eq!(
            choose_peer(&peers, &latencies, 0.5).as_deref(),
            Some("balanced")
        );
    }

    #[test]
    fn untested_latency_assumes_mid_value() {
        // 没测过的按 300ms 估：会比实测 900ms 的更划算。
        let peers = vec![peer("untested", 3), peer("slow", 3)];
        let mut latencies = std::collections::HashMap::new();
        latencies.insert("slow".to_string(), 900);
        assert_eq!(
            choose_peer(&peers, &latencies, 1.0).as_deref(),
            Some("untested")
        );
    }

    #[test]
    fn old_onion_config_still_parses() {
        let id = "ab".repeat(32);
        let json = format!(r#"{{"enabled":true,"relays":["{id}"]}}"#);
        let cfg: OnionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg.mode, OnionMode::Static);
        assert_eq!(cfg.relays.len(), 1);
        assert_eq!(cfg.relays[0].peer_id, id);
        assert_eq!(cfg.relays[0].priority, 0);
        assert_eq!(cfg.hops, 2);
        assert_eq!(cfg.weight, 0.5);
    }

    #[test]
    fn new_onion_config_roundtrips() {
        let cfg = OnionConfig {
            enabled: true,
            mode: OnionMode::Dynamic,
            relays: vec![OnionRelay {
                peer_id: "cd".repeat(32),
                priority: 7,
            }],
            hops: 3,
            weight: 0.8,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: OnionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.mode, OnionMode::Dynamic);
        assert_eq!(back.relays[0].priority, 7);
        assert_eq!(back.hops, 3);
        assert_eq!(back.weight, 0.8);
    }
}

/// 洋葱路径模式：静态按配置顺序走，动态每次随机挑。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnionMode {
    #[default]
    Static,
    Dynamic,
}

/// 一个中继节点。
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct OnionRelay {
    pub peer_id: String,
    /// 0..=9，动态模式下和延迟一起决定被选中的概率。
    #[serde(default)]
    pub priority: i64,
}

/// 洋葱路由配置。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OnionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: OnionMode,
    /// 中继池；静态模式按这个顺序走，动态模式从这里随机挑。
    #[serde(default, deserialize_with = "de_relays")]
    pub relays: Vec<OnionRelay>,
    /// 动态模式走几跳（1..=5，池子不够就全用上）。
    #[serde(default = "default_hops")]
    pub hops: u8,
    /// 选路权重 0..=1：0 = 只看优先级，1 = 只看延迟。
    #[serde(default = "default_weight")]
    pub weight: f64,
}

fn default_hops() -> u8 {
    2
}

fn default_weight() -> f64 {
    0.5
}

impl Default for OnionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: OnionMode::Static,
            relays: Vec::new(),
            hops: default_hops(),
            weight: default_weight(),
        }
    }
}

/// 老配置里 relays 是 `["id", ...]`，新配置是 `[{"peer_id":..,"priority":..}]`，
/// 两种都要能读。
#[derive(serde::Deserialize)]
#[serde(untagged)]
enum RelayRaw {
    Id(String),
    Full(OnionRelay),
}

fn de_relays<'de, D>(deserializer: D) -> Result<Vec<OnionRelay>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = <Vec<RelayRaw> as serde::Deserialize>::deserialize(deserializer)?;
    Ok(raw
        .into_iter()
        .map(|relay| match relay {
            RelayRaw::Id(peer_id) => OnionRelay {
                peer_id,
                priority: 0,
            },
            RelayRaw::Full(relay) => relay,
        })
        .collect())
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
    /// 中继实测延迟缓存（动态选路用；不落库）。
    relay_latency: Arc<Mutex<HashMap<String, u64>>>,
    /// 信箱实测延迟缓存（选信箱用；不落库）。
    mailbox_latency: Arc<Mutex<HashMap<String, u64>>>,
    /// 信箱选路权重 0..=1。
    mailbox_weight: Arc<Mutex<f64>>,
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
        let relay_latency = Arc::new(Mutex::new(HashMap::new()));
        let mailbox_latency = Arc::new(Mutex::new(HashMap::new()));
        let mailbox_weight = Arc::new(Mutex::new(store.load_mailbox_weight().unwrap_or(0.5)));
        let queue_api = Arc::new(IrohQueues::new(
            transport.clone(),
            onion.clone(),
            relay_latency.clone(),
        ));
        let onion_enabled = {
            let cfg = onion.lock().await;
            cfg.enabled && !cfg.relays.is_empty()
        };
        let links = Arc::new(LinkManager::load(store.clone(), queue_api).await?);
        links
            .set_pool(peer_ids(&mailbox_peers.lock().await.clone()))
            .await;
        links.set_onion_enabled(onion_enabled);
        let (stop_tx, _) = watch::channel(false);
        Ok(Self {
            transport,
            store,
            links,
            mailbox_peers,
            onion,
            relay_latency,
            mailbox_latency,
            mailbox_weight,
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

    /// 删除连接。
    pub async fn delete_connection(&self, conn_id: &str) -> Result<()> {
        self.links.delete(conn_id).await
    }

    /// 手动轮换入站队列。
    pub async fn rotate_connection(&self, conn_id: &str) -> Result<()> {
        self.links.rotate(conn_id).await
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
            kind: "text".into(),
            name: None,
            mime: None,
            data: None,
        });
        Ok(())
    }

    /// 发一个附件（≤2MB，图片也走这里）。
    pub async fn send_file(
        &self,
        conn_id: &str,
        name: &str,
        mime: &str,
        data: Vec<u8>,
    ) -> Result<()> {
        self.links.send_file(conn_id, name, mime, &data).await?;
        let time = now_ms();
        let _ = self.store.append_conn_message(&ConnMessage {
            conn_id: conn_id.to_string(),
            msg_id: next_msg_id("me-file", time),
            sender: "me".into(),
            text: name.to_string(),
            time,
            kind: "file".into(),
            name: Some(name.to_string()),
            mime: Some(mime.to_string()),
            data: Some(data),
        });
        Ok(())
    }

    /// 取走并解密该连接的全部待收消息（入库，返回给上层做提示用）。
    pub async fn poll_connection(&self, conn_id: &str) -> Result<Vec<String>> {
        let frames = self.links.poll(conn_id).await?;
        let mut out = Vec::new();
        for (i, frame) in frames.into_iter().enumerate() {
            let time = now_ms() + i as u64;
            match frame {
                crate::layers::links::ReceivedFrame::Text(text) => {
                    let _ = self.store.append_conn_message(&ConnMessage {
                        conn_id: conn_id.to_string(),
                        msg_id: next_msg_id("peer", time),
                        sender: "peer".into(),
                        text: text.clone(),
                        time,
                        kind: "text".into(),
                        name: None,
                        mime: None,
                        data: None,
                    });
                    out.push(text);
                }
                crate::layers::links::ReceivedFrame::File { name, mime, data } => {
                    let _ = self.store.append_conn_message(&ConnMessage {
                        conn_id: conn_id.to_string(),
                        msg_id: next_msg_id("peer-file", time),
                        sender: "peer".into(),
                        text: name.clone(),
                        time,
                        kind: "file".into(),
                        name: Some(name.clone()),
                        mime: Some(mime),
                        data: Some(data),
                    });
                    out.push(name);
                }
            }
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

    pub async fn set_onion_config(&self, mut config: OnionConfig) -> Result<()> {
        // 收一下边界，别让前端传进来的奇怪数值把选路算坏。
        config.hops = config.hops.clamp(1, 5);
        config.weight = clamp_weight(config.weight);
        for relay in &mut config.relays {
            relay.priority = relay.priority.clamp(0, 9);
        }
        config.relays.retain(|relay| {
            relay.peer_id.len() == 64 && relay.peer_id.chars().all(|c| c.is_ascii_hexdigit())
        });
        let json = serde_json::to_string(&config)?;
        self.store.save_onion_config(&json)?;
        self.links
            .set_onion_enabled(config.enabled && !config.relays.is_empty());
        *self.onion.lock().await = config;
        Ok(())
    }

    /// 测中继延迟：连一下 ONION_ALPN 看看握手要多久（不真的发请求）。
    pub async fn test_relays(&self) -> Vec<RelayPing> {
        let relays = self.onion.lock().await.relays.clone();
        if relays.is_empty() {
            return Vec::new();
        }
        let Ok(local_id) = self.transport.create_identity().await else {
            return relays
                .iter()
                .map(|relay| RelayPing::failed(&relay.peer_id, "创建拨号身份失败"))
                .collect();
        };
        let endpoint = match self.transport.endpoint_for(&local_id).await {
            Ok(endpoint) => endpoint,
            Err(e) => {
                self.transport.forget(&local_id).await;
                return relays
                    .iter()
                    .map(|relay| RelayPing::failed(&relay.peer_id, &e.to_string()))
                    .collect();
            }
        };

        let mut set = tokio::task::JoinSet::new();
        for relay in relays {
            let endpoint = endpoint.clone();
            let peer_id = relay.peer_id.clone();
            set.spawn(async move {
                let started = std::time::Instant::now();
                let result = match peer_id.parse::<iroh::EndpointId>() {
                    Ok(id) => tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        endpoint.connect(iroh::EndpointAddr::new(id), privchat_onion::ONION_ALPN),
                    )
                    .await
                    .map_err(|_| "连接超时".to_string())
                    .and_then(|r| r.map_err(|e| e.to_string())),
                    Err(_) => Err("节点 ID 不合法".to_string()),
                };
                let ms = started.elapsed().as_millis() as u64;
                match result {
                    Ok(conn) => {
                        // 只测握手，立刻断开。
                        drop(conn);
                        RelayPing {
                            peer_id,
                            ms: Some(ms),
                            error: None,
                        }
                    }
                    Err(error) => RelayPing {
                        peer_id,
                        ms: None,
                        error: Some(error),
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
        {
            let mut cache = self.relay_latency.lock().await;
            for ping in &out {
                if let Some(ms) = ping.ms {
                    cache.insert(ping.peer_id.clone(), ms);
                } else {
                    cache.remove(&ping.peer_id);
                }
            }
        }
        self.transport.forget(&local_id).await;
        out
    }

    pub async fn get_relay_latency(&self) -> HashMap<String, u64> {
        self.relay_latency.lock().await.clone()
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
        {
            let mut cache = self.mailbox_latency.lock().await;
            for ping in &out {
                match ping.ms {
                    Some(ms) => {
                        cache.insert(ping.peer_id.clone(), ms);
                    }
                    None => {
                        cache.remove(&ping.peer_id);
                    }
                }
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

    /// 挑一台信箱建队列：优先级和延迟按权重打分，取分数最低的。
    pub async fn pick_mailbox(&self) -> Result<String> {
        let peers = self.mailbox_peers.lock().await.clone();
        if peers.is_empty() {
            return Err(anyhow!("还没有配置信箱节点"));
        }
        let weight = *self.mailbox_weight.lock().await;
        let mut latencies = self.mailbox_latency.lock().await.clone();
        // 还没测过速就先测一轮——不然延迟这一项全是估的。
        if latencies.is_empty() {
            let ids: Vec<String> = peers.iter().map(|p| p.peer_id.clone()).collect();
            for ping in self.ping_mailboxes(&ids).await {
                if let Some(ms) = ping.ms {
                    latencies.insert(ping.peer_id, ms);
                }
            }
        }
        Ok(choose_peer(&peers, &latencies, weight).unwrap_or_else(|| peers[0].peer_id.clone()))
    }

    pub async fn get_mailbox_weight(&self) -> f64 {
        *self.mailbox_weight.lock().await
    }

    pub async fn set_mailbox_weight(&self, weight: f64) -> Result<()> {
        let weight = clamp_weight(weight);
        self.store.save_mailbox_weight(weight)?;
        *self.mailbox_weight.lock().await = weight;
        Ok(())
    }

    pub async fn get_mailbox_latency(&self) -> HashMap<String, u64> {
        self.mailbox_latency.lock().await.clone()
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
