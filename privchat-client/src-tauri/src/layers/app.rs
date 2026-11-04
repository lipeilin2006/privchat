//! Layer 2 应用与状态层 (App & Local Storage, Local-First)
//!
//! 基于 iroh QUIC 的应用门面：本层负责身份、联系人、消息历史与投递；
//! 端到端加密在 `crypto`（双棘轮，Layer 2.5），离线缓存走 `mailbox`。
//!
//! ## 每联系人独立身份（无主身份）
//!
//! 为防止跨联系人关联分析，每个联系人使用**专属身份**（独立 SecretKey +
//! 独立 iroh Endpoint），本端没有固定主身份。邀请串 = 该联系人专属身份
//! 的 peer_id：每次打开添加联系人界面都会新建一个专属身份并分享其 peer_id；
//! 对方连接后经 TLS 认证自动绑定；本端与该联系人对话始终用这个专属身份，
//! 跨联系人不关联。
//!
//! `local_id`（本端为该联系人保留的专属身份）与联系人一一对应：接收消息
//! 时凭 `local_id` 即可在联系人表唯一确定发送方 peer_id，因此 wire 消息中
//! 不再需要 `from_peer_id` 字段（直连由 TLS 认证，mailbox 由队列归属唯一
//! 推导）。mailbox 队列按 `local_id` 分类 → 每队列单发送方，消息顺序即
//! 发送方棘轮 `(gen, n)` 顺序。
//!
//! 持久化由 `store`（SQLCipher 全库加密）提供。
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot, watch, Mutex};
use tokio::task::JoinHandle;

use super::crypto;
use super::mailbox::{MailboxClient, StoredMessage};
use super::transport::{IncomingEnvelope, Transport};

/// 洋葱路由配置：是否启用 + 中继路径（最后一跳应为 mailbox 节点）。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OnionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub relays: Vec<String>,
}

/// 应用层消息（前后端共享结构）。`id` 为消息 ID（由棘轮序号和密文派生），
/// 用于跨直连/mailbox 双通道投递去重。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: String,
    pub from: String,
    pub text: String,
    pub time: u64,
}

/// wire 层统一消息结构（直连与 mailbox 共用）。
///
/// 直连：序列化为 JSON 经 QUIC 传输，其中 `msg` 为应用层加密的 `PlainMsg`；
/// mailbox：`msg` 即为存入节点的密文，元数据（msg_id/to）明文供节点分类
/// 去重与同步。*不含 from*：接收方凭本端专属身份（`local_id`）在联系人
/// 表唯一确定发送方 peer_id（直连由 TLS 认证，mailbox 由队列归属唯一推导）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireMessage {
    pub msg_id: String,
    pub to_peer_id: String,
    /// 加密后的消息内容：`nonce(12) || ciphertext(PlainMsg)`。
    pub msg: Vec<u8>,
}

/// wire 消息中加密承载的明文内容。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlainMsg {
    pub msg_text: String,
    pub utc_time: u64,
}

/// 生成消息 ID：`{gen:08x}{n:08x}{发送方身份前8hex}{密文哈希前16hex}`。
///
/// `(gen, n)` 取自加密后的消息头 —— 发送方的绝对逻辑发送序
/// （Epoch=DH 刷新代，Seq=本代内链计数）。mailbox 按 msg_id 升序即按
/// (gen, n) 升序返回，等于棘轮消息顺序；且不含墙钟，不泄露收发时间。
/// gen 为 u32，杜绝刷新回绕。
///
/// 哈希后缀让公开 mailbox 无法只凭可预测的 `(gen,n)` 提前抢占 ID；接收端
/// 会根据认证发送方和密文重算 ID。相同密文的重试仍得到相同 ID。
///
/// **跨方向唯一**：双方各从 gen0/n0 开始，仅 `(gen, n)` 会在同一会话的
/// 收发两侧撞车（我发的第 0 条 == 对方发的第 0 条）。后缀取发送方专属
/// 身份的前 8 hex 作为方向区分符，且对同一条消息两侧计算一致
/// （发送侧在此处生成，接收侧会重新校验），因此不会破坏重试去重。
fn msg_id_for(local_id: &str, blob: &[u8]) -> String {
    let (gen, n) = crypto::Ratchet::header_gen_n(blob).unwrap_or((0, 0));
    let who = local_id.chars().take(8).collect::<String>();
    let digest = Sha256::digest(blob);
    let hash = digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{gen:08x}{n:08x}{who}{hash}")
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 每会话发送队列表：`(local_id, peer_id) -> 该会话发送 worker 的投递通道`。
mod inbox;
mod outbox;
mod poll;
mod session;

use outbox::{run_send_worker, SendCtx, SendJob};
use poll::PollApp;
use session::{elect_active, SessionEntry, SessionMap, SessionRole};

type SendQueues = Arc<Mutex<HashMap<(String, String), mpsc::UnboundedSender<SendJob>>>>;

/// L4 应用门面。
#[derive(Clone)]
pub struct App {
    transport: Transport,
    /// SQLite 持久化。
    store: Arc<super::store::Store>,
    /// 持久化的好友表（peer_id -> 联系人信息）。
    contacts: Arc<Mutex<HashMap<String, Contact>>>,
    /// 每会话消息历史（peer_id -> 消息列表，按时间升序）。
    history: Arc<Mutex<HashMap<String, Vec<ChatMessage>>>>,
    /// 配置的 mailbox 节点 peer_id 列表（空 = 未启用离线消息）。
    mailbox_peers: Arc<Mutex<Vec<String>>>,
    /// 每条离线消息写入的 mailbox 节点数（0 = 全部已配置节点）。
    mailbox_write_count: Arc<AtomicUsize>,
    /// 洋葱路由配置（relay 路径 + 开关）。
    onion: Arc<Mutex<OnionConfig>>,
    /// 是否保留 P2P 直连投递（仅测试模式为 true）。
    allow_direct: bool,
    /// 待绑定专属身份（已生成邀请但尚未被连接的 local_id）。
    pending: Arc<Mutex<Vec<String>>>,
    /// 会话缓存：`(local_id, peer_id) -> Vec<SessionEntry>`。
    /// 一条联系人可有多条会话（并发发起），主会话负责发送，其余只解密。
    sessions: SessionMap,
    /// 每会话发送队列：`(local_id, peer_id) -> 发送 worker 的投递通道`。
    ///
    /// 发送在同一会话内串行化（一条一条发）：保证每条消息拿到递增且唯一的
    /// `(gen, n)`，避免并发加密读到相同状态导致 msg_id 重复、接收方去重丢弃；
    /// 且某条发送失败（对端断连且无 mailbox 兜底）时，快速失败队列中剩余消息，
    /// 不会让每条都再等一个 10s 超时。
    send_queues: SendQueues,
    /// mailbox 轮询任务是否已启动（运行期动态添加 mailbox 节点时用）。
    mailbox_poll_started: Arc<AtomicBool>,
    mailbox_poll_task: Arc<Mutex<Option<JoinHandle<()>>>>,
    stop_tx: watch::Sender<bool>,
    worker_tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

/// 持久化的联系人记录：足以在重启后重新建立连接。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    /// 对方 EndpointId（即 peer_id，对方专属身份）。
    pub peer_id: String,
    /// 本端为该联系人使用的专属身份（本地身份 peer_id）。
    #[serde(default)]
    pub local_id: String,
    /// 前端展示名（可选，缺省为 peer_id 前缀）。
    pub name: Option<String>,
    /// 对方的连接票据（重启后重新拨号）。单边邀请下对方未提供票据时为空。
    pub ticket: Option<String>,
    /// 对方的 X25519 SPK 公钥（来自邀请串，X3DH 用）。
    #[serde(default)]
    pub peer_spk: Option<Vec<u8>>,
}

/// 前端联系人列表条目（轻量）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactSummary {
    pub peer_id: String,
    pub name: String,
    /// 本端为该联系人使用的专属身份（前端据此判断消息归属）。
    pub local_id: String,
}

impl App {
    pub async fn start(
        data_dir: PathBuf,
        key: [u8; 32],
    ) -> Result<(Self, mpsc::UnboundedReceiver<IncomingEnvelope>)> {
        Self::start_inner(data_dir, true, key).await
    }

    /// 无 relay 单机模式，用于集成测试。
    #[cfg(test)]
    pub async fn start_no_relay(
        data_dir: PathBuf,
        key: [u8; 32],
    ) -> Result<(Self, mpsc::UnboundedReceiver<IncomingEnvelope>)> {
        Self::start_inner(data_dir, false, key).await
    }

    async fn start_inner(
        data_dir: PathBuf,
        use_relay: bool,
        key: [u8; 32],
    ) -> Result<(Self, mpsc::UnboundedReceiver<IncomingEnvelope>)> {
        let store = Arc::new(super::store::Store::open(&data_dir, key)?);
        let (transport, rx) = if use_relay {
            Transport::start(store.clone()).await?
        } else {
            Transport::start_no_relay(store.clone()).await?
        };

        let contacts = store.load_contacts()?;
        let bound_ids: HashSet<String> = contacts
            .values()
            .map(|contact| contact.local_id.clone())
            .collect();
        let cutoff = now_ms().saturating_sub(super::store::UNBOUND_IDENTITY_TTL_MS);
        for local_id in store.delete_expired_unbound_identities(&bound_ids, cutoff)? {
            eprintln!("[app] removed expired unbound identity {local_id}");
        }
        let contacts = Arc::new(Mutex::new(contacts));
        let history = Arc::new(Mutex::new(store.load_history()?));

        // 待绑定身份：磁盘上已持久化、但未被任何联系人引用的专属身份。
        let pending = Arc::new(Mutex::new(Vec::new()));
        {
            let mut pend = pending.lock().await;
            for id in transport.local_ids().await {
                let used = contacts.lock().await.values().any(|c| c.local_id == id);
                if !used {
                    pend.push(id);
                }
            }
        }

        // 重启后重放已有联系人的专属身份与拨号注册。
        for contact in contacts.lock().await.values().cloned().collect::<Vec<_>>() {
            transport.ensure_identity(&contact.local_id).await?;
            // 单边邀请建立的联系人可能没有对方票据，只能等对方先连。
            let addr = contact.ticket.as_deref().unwrap_or(&contact.peer_id);
            transport.connect_peer(&contact.local_id, addr).await?;
        }

        // mailbox 客户端：复用各联系人专属身份的 Endpoint。仅生产模式
        // （relay）启动轮询；no-relay 集成测试不启用，避免后台任务持有
        // 端口阻塞重启。
        let mailbox_peers = Arc::new(Mutex::new(store.load_mailbox_peers()?));
        // 每条离线消息写入的 mailbox 节点数（0 = 全部已配置节点）。
        let mailbox_write_count = Arc::new(AtomicUsize::new(store.load_mailbox_write_count()?));

        // 会话：从磁盘恢复（需要各专属身份私钥还原 root₀ 与链状态）。
        let identities = store.load_identities()?;
        let mut session_map: HashMap<(String, String), Vec<SessionEntry>> = HashMap::new();
        for (sid, local_id, peer_id, role, active, state) in store.load_sessions()? {
            let Some(secret_bytes) = identities.get(&local_id) else {
                continue;
            };
            let Ok(secret) = iroh::SecretKey::try_from(secret_bytes.as_slice()) else {
                continue;
            };
            let Some(role) = SessionRole::from_str(&role) else {
                continue;
            };
            match crypto::Ratchet::from_bytes(&secret, &peer_id, &state) {
                Ok(ratchet) => {
                    session_map
                        .entry((local_id, peer_id))
                        .or_default()
                        .push(SessionEntry {
                            id: sid,
                            role,
                            ratchet,
                            active,
                        })
                }
                Err(e) => {
                    eprintln!("[app] discarded incompatible session state: {e}");
                }
            }
        }
        for entries in session_map.values_mut() {
            elect_active(entries);
        }
        let sessions = Arc::new(Mutex::new(session_map));
        let send_queues = Arc::new(Mutex::new(HashMap::new()));
        let mailbox_poll_started = Arc::new(AtomicBool::new(false));
        let mailbox_poll_task = Arc::new(Mutex::new(None));
        let (stop_tx, _) = watch::channel(false);
        let worker_tasks = Arc::new(Mutex::new(Vec::new()));
        let onion = Arc::new(Mutex::new(
            store
                .load_onion_config()
                .ok()
                .and_then(|json| serde_json::from_str::<OnionConfig>(&json).ok())
                .unwrap_or_default(),
        ));

        let app = Self {
            transport,
            store,
            contacts,
            history,
            mailbox_peers,
            mailbox_write_count,
            onion,
            allow_direct: !use_relay,
            pending,
            sessions,
            send_queues,
            mailbox_poll_started,
            mailbox_poll_task,
            stop_tx,
            worker_tasks,
        };

        if use_relay && !app.mailbox_peers.lock().await.is_empty() {
            app.mailbox_poll_started.store(true, Ordering::Relaxed);
            app.start_mailbox_poll(app.transport.incoming_sender())
                .await;
        }

        Ok((app, rx))
    }

    /// 本端可分享的邀请串 = 新专属身份的 peer_id（几十字符，适合二维码）。
    ///
    /// 每次调用都新建一个专属身份并持久化，返回其 peer_id 作为邀请串；
    /// 若之后建立联系人时优先绑定该身份。与旧「复用未绑定邀请身份」的
    /// 行为不同：每开一次添加联系人界面就产生一个新的、独立的 peer_id。
    pub async fn self_ticket(&self) -> String {
        match self.transport.create_identity().await {
            Ok(local_id) => {
                self.pending.lock().await.push(local_id.clone());
                // 邀请串 = IK + SPK 公钥 + IK 签名，加到通讯录时验签。
                match (
                    self.transport.secret_for(&local_id).await,
                    self.transport.spk_public(&local_id).await,
                ) {
                    // 生产邀请不带地址（避免泄漏 IP/relay），靠 DNS 发现。
                    (Ok(secret), Ok(spk_pk)) => crypto::encode_invite(&secret, &spk_pk, None),
                    _ => String::new(),
                }
            }
            Err(e) => {
                eprintln!("[app] create identity failed: {e}");
                String::new()
            }
        }
    }

    pub async fn delete_pending_identity(&self, local_id: &str) -> Result<()> {
        if self
            .contacts
            .lock()
            .await
            .values()
            .any(|contact| contact.local_id == local_id)
        {
            return Err(anyhow!("identity is bound to a contact"));
        }
        self.pending.lock().await.retain(|id| id != local_id);
        self.transport.drop_identity(local_id).await;
        Ok(())
    }

    /// 当前配置的 mailbox 节点 peer_id 列表（空 = 未启用离线消息）。
    /// 读取洋葱路由配置。
    pub async fn get_onion_config(&self) -> OnionConfig {
        self.onion.lock().await.clone()
    }

    /// 保存洋葱路由配置（校验每个中继 id 必须是 64 位十六进制）。
    pub async fn set_onion_config(&self, config: OnionConfig) -> Result<()> {
        for relay in &config.relays {
            if relay.len() != 64 || !relay.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(anyhow!("invalid relay peer id: {relay}"));
            }
        }
        if config.enabled && config.relays.is_empty() {
            return Err(anyhow!("onion routing enabled but relay path is empty"));
        }
        self.store
            .save_onion_config(&serde_json::to_string(&config)?)?;
        *self.onion.lock().await = config;
        Ok(())
    }

    pub async fn get_mailbox_peers(&self) -> Vec<String> {
        self.mailbox_peers.lock().await.clone()
    }

    pub async fn ping_mailbox(&self, peer_id: &str) -> Result<u64> {
        let local_id = self
            .transport
            .local_ids()
            .await
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("identity recovery failed"))?;
        let endpoint = self.transport.endpoint_for(&local_id).await?;
        let started = std::time::Instant::now();
        super::mailbox::MailboxClient::ping(&endpoint, peer_id).await?;
        Ok(started.elapsed().as_millis() as u64)
    }

    /// 每条离线消息写入的 mailbox 节点数（0 = 全部已配置节点）。
    pub async fn get_mailbox_write_count(&self) -> usize {
        self.mailbox_write_count.load(Ordering::Relaxed)
    }

    pub fn get_auto_lock_minutes(&self) -> Result<u64> {
        self.store.load_auto_lock_minutes()
    }

    pub fn set_auto_lock_minutes(&self, minutes: u64) -> Result<()> {
        self.store.save_auto_lock_minutes(minutes)
    }

    /// 设置每条离线消息写入的 mailbox 节点数（0 = 全部已配置节点），持久化。
    pub async fn set_mailbox_write_count(&self, count: usize) -> Result<()> {
        self.store.save_mailbox_write_count(count)?;
        self.mailbox_write_count.store(count, Ordering::Relaxed);
        Ok(())
    }

    /// 追加一个 mailbox 节点（去重后持久化）。
    ///
    /// 若此前尚未启动 mailbox 轮询（例如启动时未配置任何节点），则在首个
    /// 节点加入时启动后台轮询，避免离线消息静默失效。
    pub async fn add_mailbox_peer(&self, peer_id: &str) -> Result<()> {
        let mut peers = self.mailbox_peers.lock().await;
        let peer = peer_id.trim().to_string();
        if !peer.is_empty() && !peers.contains(&peer) {
            peers.push(peer);
        }
        let snapshot = peers.clone();
        drop(peers);
        self.persist_mailbox_peers(&snapshot)?;
        if !self.mailbox_poll_started.swap(true, Ordering::Relaxed) {
            self.start_mailbox_poll(self.transport.incoming_sender())
                .await;
        }
        Ok(())
    }

    /// 移除一个 mailbox 节点并持久化。
    pub async fn remove_mailbox_peer(&self, peer_id: &str) -> Result<()> {
        let mut peers = self.mailbox_peers.lock().await;
        peers.retain(|p| p != peer_id);
        let snapshot = peers.clone();
        drop(peers);
        self.persist_mailbox_peers(&snapshot)?;
        Ok(())
    }

    fn persist_mailbox_peers(&self, peers: &[String]) -> Result<()> {
        self.store.save_mailbox_peers(peers)?;
        Ok(())
    }

    /// 后台轮询任务：每 20 秒从 mailbox 拉取全部联系人的待收密文，
    /// 解密后注入入站通道（走与直连相同的 handle_incoming/前端 emit
    /// 流程），成功后 ACK。
    async fn start_mailbox_poll(&self, tx: mpsc::UnboundedSender<IncomingEnvelope>) {
        let mut task = self.mailbox_poll_task.lock().await;
        if task.is_some() {
            return;
        }
        let app = PollApp {
            transport: self.transport.clone(),
            mailbox_peers: self.mailbox_peers.clone(),
            history: self.history.clone(),
            contacts: self.contacts.clone(),
        };
        let mut stop = self.stop_tx.subscribe();
        *task = Some(tokio::spawn(async move {
            let interval = std::time::Duration::from_secs(20);
            loop {
                tokio::select! {
                    _ = stop.changed() => break,
                    _ = app.poll_mailbox_once(tx.clone()) => {}
                }
                tokio::select! {
                    _ = stop.changed() => break,
                    _ = tokio::time::sleep(interval) => {}
                }
            }
        }));
    }

    /// 停止轮询、发送队列、入站网络和所有身份端点。
    pub async fn shutdown(&self) {
        let _ = self.stop_tx.send(true);
        if let Some(task) = self.mailbox_poll_task.lock().await.take() {
            task.abort();
            let _ = task.await;
        }
        self.mailbox_poll_started.store(false, Ordering::Relaxed);
        self.send_queues.lock().await.clear();
        let tasks = std::mem::take(&mut *self.worker_tasks.lock().await);
        for task in tasks {
            let _ = task.await;
        }
        self.sessions.lock().await.clear();
        self.transport.close().await;
    }

    /// 主动关闭全部底层连接（重启测试用）。
    #[cfg(test)]
    pub async fn close(&self) {
        self.transport.close().await;
    }

    /// 已知联系人列表（peer_id + 展示名 + 本端专属身份），供前端展示。
    pub async fn list_contacts(&self) -> Vec<ContactSummary> {
        let contacts = self.contacts.lock().await;
        let mut out: Vec<ContactSummary> = contacts
            .values()
            .map(|c| ContactSummary {
                peer_id: c.peer_id.clone(),
                name: c
                    .name
                    .clone()
                    .unwrap_or_else(|| c.peer_id.chars().take(10).collect()),
                local_id: c.local_id.clone(),
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// 某会话的历史消息（时间升序）。
    pub async fn get_history(&self, peer_id: &str) -> Vec<ChatMessage> {
        self.history
            .lock()
            .await
            .get(peer_id)
            .cloned()
            .unwrap_or_default()
    }

    pub fn load_draft(&self, peer_id: &str) -> Result<String> {
        self.store.load_draft(peer_id)
    }

    pub fn save_draft(&self, peer_id: &str, text: &str) -> Result<()> {
        self.store.save_draft(peer_id, text)
    }

    pub fn search_messages(&self, query: &str, limit: usize) -> Result<Vec<(String, ChatMessage)>> {
        self.store.search_messages(query, limit)
    }

    /// 删除联系人：移除联系人表、专属身份与历史会话。
    pub async fn delete_contact(&self, peer_id: &str) -> Result<()> {
        let local_id = self
            .contacts
            .lock()
            .await
            .get(peer_id)
            .cloned()
            .map(|c| c.local_id);
        self.contacts.lock().await.remove(peer_id);
        self.history.lock().await.remove(peer_id);
        if let Some(local_id) = local_id {
            // 停掉该会话的发送 worker：移除队列条目后 send_queues 中的 tx 被
            // drop，worker 的 rx 随之关闭并退出，避免其常驻持有 transport/
            // store/ratchets 等引用。
            self.send_queues
                .lock()
                .await
                .remove(&(local_id.clone(), peer_id.to_string()));
            // 删除专属身份与会话：会话密钥（棘轮）一并销毁，实现会话级前向保密。
            self.sessions
                .lock()
                .await
                .remove(&(local_id.clone(), peer_id.to_string()));
            if let Err(e) = self.store.delete_sessions(&local_id) {
                eprintln!("[app] failed to delete ratchet for {local_id}: {e}");
            }
            self.transport.drop_identity(&local_id).await;
            self.pending.lock().await.retain(|id| id != &local_id);
        }
        self.store.save_draft(peer_id, "")?;
        self.persist_contacts().await;
        self.persist_history().await;
        Ok(())
    }

    /// 重命名联系人（前端展示名），持久化后返回更新后的摘要。
    pub async fn rename_contact(&self, peer_id: &str, name: &str) -> Result<ContactSummary> {
        let trimmed = name.trim().to_string();
        if trimmed.is_empty() {
            return Err(anyhow!("name must not be empty"));
        }
        let mut contacts = self.contacts.lock().await;
        let contact = contacts
            .get_mut(peer_id)
            .ok_or_else(|| anyhow!("unknown peer: {peer_id}"))?;
        contact.name = Some(trimmed.clone());
        let summary = ContactSummary {
            peer_id: peer_id.to_string(),
            name: trimmed,
            local_id: contact.local_id.clone(),
        };
        drop(contacts);
        self.persist_contacts().await;
        Ok(summary)
    }

    /// 通过邀请串（纯 peer_id 或完整票据）建立好友关系，返回对方 peer_id。
    ///
    /// 本端为对方生成/复用一个新的专属身份作为本地身份；若已有待绑定邀请
    /// 身份（`self_ticket` 新建）则绑定给该联系人，否则新建。
    /// **防冲突**：选中的本地身份必须未被任何联系人占用，否则跳过重选。
    pub async fn connect_peer(&self, invite: &str, name: Option<String>) -> Result<String> {
        // 邀请串 = IK + SPK + 签名；先验签再取身份。
        let (invite_peer, spk, invite_ticket) = crypto::parse_invite(invite)?;
        let _remote = self.transport.parse_peer_id(&invite_peer)?;

        // 复用未被占用的待绑定邀请身份；无则新建。
        let local_id = {
            let contacts = self.contacts.lock().await;
            let mut pending = self.pending.lock().await;
            let mut idx = None;
            for (i, id) in pending.iter().enumerate() {
                if !contacts.values().any(|c| c.local_id == *id) {
                    idx = Some(i);
                    break;
                }
            }
            match idx {
                Some(i) => pending.remove(i),
                None => self.transport.create_identity().await?,
            }
        };

        // 邀请里带票据就用票据拨号（免 DNS）；否则按 peer_id 走 DNS 发现。
        let dial = invite_ticket.as_deref().unwrap_or(&invite_peer);
        let peer_id = self.transport.connect_peer(&local_id, dial).await?;
        let contact = Contact {
            peer_id: peer_id.clone(),
            local_id,
            name,
            // 存「拨号地址」（票据或 peer_id），不是邀请串本身。
            ticket: Some(dial.to_string()),
            peer_spk: Some(spk.to_vec()),
        };
        self.contacts.lock().await.insert(peer_id.clone(), contact);
        self.persist_contacts().await;
        Ok(peer_id)
    }

    /// 把联系人表写入 SQLite。
    async fn persist_contacts(&self) {
        let contacts = self.contacts.lock().await.clone();
        if let Err(e) = self.store.save_contacts(&contacts) {
            eprintln!("[app] failed to persist contacts: {e}");
        }
    }

    /// 把一条消息追加进历史并写入 SQLite（按 msg_id 幂等）。
    async fn append_history(&self, peer_id: &str, msg: ChatMessage) {
        let mut history = self.history.lock().await;
        let conv = history.entry(peer_id.to_string()).or_default();
        if !conv.iter().any(|m| m.id == msg.id) {
            conv.push(msg);
        }
        drop(history);
        self.persist_history().await;
    }

    /// 把整个历史表写入 SQLite。
    async fn persist_history(&self) {
        let history = self.history.lock().await.clone();
        if let Err(e) = self.store.save_history(&history) {
            eprintln!("[app] failed to persist history: {e}");
        }
    }

    /// 发送一条文本消息，返回本端已发出的 ChatMessage。
    ///
    /// 消息统一为 wire 层 `pack { msg_id, to_peer_id, msg }`，其中 `msg`
    /// 为应用层加密的 `{ msg_text, utc_time }`。直连与 mailbox 共用同一
    /// 结构：直连传完整 pack，mailbox 传 pack 的元数据 + 密文 msg。
    /// pack 不含 from：接收方凭本端专属身份唯一确定发送方。
    ///
    /// 发送走每会话串行队列：同一会话的消息一条一条发出，保证每条消息
    /// 拿到递增且唯一的 `(gen, n)`（并发直接加密会读到相同的未提交状态，
    /// 产生相同 msg_id，接收方去重会丢弃后面几条）；对端断连且无 mailbox
    /// 兜底时，队列中剩余消息快速失败（不再各自等 10s 超时）。
    pub async fn send_message(&self, peer_id: &str, text: &str) -> Result<ChatMessage> {
        let utc_time = now_ms();
        let contact = self
            .contacts
            .lock()
            .await
            .get(peer_id)
            .cloned()
            .ok_or_else(|| anyhow!("unknown peer: {peer_id}"))?;
        let local_id = contact.local_id.clone();

        let plain = PlainMsg {
            msg_text: text.to_string(),
            utc_time,
        };
        // 加密前做桶填充：同桶内消息密文长度一致，削弱长度侧信道。
        let plain_bytes = privchat_common::pad_plaintext(&serde_json::to_vec(&plain)?);

        let key = (local_id.clone(), peer_id.to_string());
        // 取该会话的发送 worker；不存在则创建一个（懒启动，之后复用）。
        let tx = {
            let mut queues = self.send_queues.lock().await;
            if let Some(tx) = queues.get(&key) {
                tx.clone()
            } else {
                let (tx, rx) = mpsc::unbounded_channel();
                let ctx = SendCtx {
                    transport: self.transport.clone(),
                    store: self.store.clone(),
                    sessions: self.sessions.clone(),
                    mailbox_peers: self.mailbox_peers.clone(),
                    mailbox_write_count: self.mailbox_write_count.clone(),
                    history: self.history.clone(),
                    contacts: self.contacts.clone(),
                    onion: self.onion.clone(),
                    allow_direct: self.allow_direct,
                    stop: self.stop_tx.subscribe(),
                };
                let key_for_worker = key.clone();
                let task = tokio::spawn(async move {
                    run_send_worker(ctx, key_for_worker, rx).await;
                });
                self.worker_tasks.lock().await.push(task);
                queues.insert(key.clone(), tx.clone());
                tx
            }
        };

        // 入队并等待该消息的发送结果（成功/失败均回传）。
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(SendJob {
            plain_bytes,
            utc_time,
            text: text.to_string(),
            reply: reply_tx,
        })
        .map_err(|_| anyhow!("send queue closed for {peer_id}"))?;
        reply_rx.await.map_err(|_| anyhow!("send worker dropped"))?
    }
}

#[cfg(test)]
mod tests;
