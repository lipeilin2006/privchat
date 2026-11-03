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
type SendQueues = Arc<Mutex<HashMap<(String, String), mpsc::UnboundedSender<SendJob>>>>;

/// 发送 worker 所需的最小状态：仅传需要的字段克隆，避免把整个 `App`
/// （含 send_queues 表，即自身所在映射）搬进任务——否则 worker 与发送
/// 通道互相持有形成自循环，App 被 drop 后 worker 仍存活、Endpoint 端口
/// 无法释放（重启/换库时端口占用）。
#[derive(Clone)]
struct SendCtx {
    transport: Transport,
    store: Arc<super::store::Store>,
    ratchets: Arc<Mutex<HashMap<(String, String), crypto::Ratchet>>>,
    mailbox_peers: Arc<Mutex<Vec<String>>>,
    /// 每条离线消息写入的 mailbox 节点数（0 = 全部已配置节点）。
    mailbox_write_count: Arc<AtomicUsize>,
    /// 洋葱路由配置（启用时 mailbox 投递走多层转发）。
    onion: Arc<Mutex<OnionConfig>>,
    /// 是否保留 P2P 直连投递（仅单机集成测试为 true；生产已删除直连）。
    allow_direct: bool,
    history: Arc<Mutex<HashMap<String, Vec<ChatMessage>>>>,
    contacts: Arc<Mutex<HashMap<String, Contact>>>,
    stop: watch::Receiver<bool>,
}

/// 发送队列中的一条待发任务：携带加密所需的最小载荷与应答通道。
struct SendJob {
    plain_bytes: Vec<u8>,
    utc_time: u64,
    text: String,
    /// 单条消息的结果回传：worker 处理完（成功/失败）后回填。
    reply: oneshot::Sender<Result<ChatMessage>>,
}

/// 单个会话的发送 worker：串行消费队列，逐条加密→投递→确认。
///
/// 每条消息：加密（在 `pending` 暂存推进，不提交）→ mailbox 兜底 →
/// 直连 → 确认送达后 `Ratchet::next` 提交并持久化。若某条消息最终
/// 未送达（无 mailbox 兜底且直连失败），则把队列中剩余消息一并快速
/// 失败（对端已断连，继续发送只会各自等一个超时）。
async fn run_send_worker(
    mut ctx: SendCtx,
    key: (String, String),
    mut rx: mpsc::UnboundedReceiver<SendJob>,
) {
    let (local_id, peer_id) = key;
    while let Some(job) = tokio::select! {
        _ = ctx.stop.changed() => None,
        job = rx.recv() => job,
    } {
        let result = ctx.send_one(&local_id, &peer_id, &job).await;
        let failed = result.is_err();
        let _ = job.reply.send(result);
        if failed {
            // 对端断连：快速失败队列中剩余的消息。
            while let Ok(rest) = rx.try_recv() {
                let _ = rest.reply.send(Err(anyhow!(
                    "send to {peer_id} failed, queued message dropped"
                )));
            }
        }
    }
}

/// 通过洋葱路径投递一条 mailbox PUT。
///
/// 路径最后一跳必须是 mailbox 节点：它剥离最后一层后按普通请求落库。
async fn onion_put(
    endpoint: &iroh::Endpoint,
    relays: &[String],
    to: &str,
    id: &str,
    payload: Vec<u8>,
) -> Result<()> {
    use privchat_common::MailboxRequest;

    let nonce = {
        let to_owned = to.to_string();
        let payload_owned = payload.clone();
        tokio::task::spawn_blocking(move || privchat_common::find_pow(&to_owned, &payload_owned))
            .await?
    };
    let request = MailboxRequest::put(to, id, payload, nonce);
    let packet = privchat_onion::wrap(relays, &serde_json::to_vec(&request)?)?;

    let first: iroh::EndpointId = relays[0]
        .parse()
        .map_err(|_| anyhow!("invalid first relay: {}", relays[0]))?;
    let conn = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        endpoint.connect(iroh::EndpointAddr::new(first), privchat_onion::ONION_ALPN),
    )
    .await
    .map_err(|_| anyhow!("onion connect timed out"))??;
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(&packet).await?;
    send.finish()?;
    let bytes = tokio::time::timeout(std::time::Duration::from_secs(30), recv.read_to_end(4096))
        .await
        .map_err(|_| anyhow!("onion ack timed out"))??;
    let response: privchat_common::MailboxResponse = serde_json::from_slice(&bytes)?;
    if !response.ok {
        return Err(anyhow!(
            "onion route rejected: {}",
            response.error.unwrap_or_default()
        ));
    }
    Ok(())
}

impl SendCtx {
    /// 单条消息的完整发送流程（加密→mailbox→直连→确认提交）。
    async fn send_one(&self, local_id: &str, peer_id: &str, job: &SendJob) -> Result<ChatMessage> {
        let secret = self.transport.secret_for(local_id).await?;

        // 加密只生成密文并在 `pending` 暂存推进，不立即提交会话状态；
        // 只有消息确认送达（直连成功，或有 mailbox 兜底）后才调用
        // `Ratchet::next` 提交并持久化。发送失败则状态保持加密前，
        // 不会污染棘轮链（gen/n 不提前、不发生收敛失步）。
        let blob = {
            let key = (local_id.to_string(), peer_id.to_string());
            let mut ratchets = self.ratchets.lock().await;
            if !ratchets.contains_key(&key) {
                // 没有会话就新建：发送方即发起方，需要对方 SPK 公钥（邀请串携带）。
                // 若本端是响应方（对方先发的），会话已存在，不查 SPK。
                let peer_spk = {
                    let contacts = self.contacts.lock().await;
                    contacts
                        .get(peer_id)
                        .and_then(|c| c.peer_spk.clone())
                        .ok_or_else(|| anyhow!("contact {peer_id} has no SPK; re-add via invite"))?
                };
                let peer_spk: [u8; 32] = peer_spk
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow!("stored peer SPK has bad length"))?;
                ratchets.insert(
                    key.clone(),
                    crypto::Ratchet::new_initiator(&secret, peer_id, &peer_spk)?,
                );
            }
            ratchets.get_mut(&key).unwrap().encrypt(&job.plain_bytes)?
        };

        // 消息 ID 由加密头 (gen, n) 派生：mailbox 按其字典序返回即等于棘轮
        // 发送序，且不泄露时间。
        let msg_id = msg_id_for(local_id, &blob);

        let wire = WireMessage {
            msg_id: msg_id.clone(),
            to_peer_id: peer_id.to_string(),
            msg: blob.clone(),
        };

        // 1) mailbox：按配置数量投放到多个节点（多副本冗余）。节点间另有
        //    自动网格同步（put→Sync 广播、取回即删→SyncAck），其余节点会
        //    自动补副本；多写只是让同一密文直接落在更多节点上，即使个别
        //    节点永久离线也不丢。任一节点成功即视为 mailbox 可用；全部
        //    失败才算 mailbox 不可用。
        let peers = self.mailbox_peers.lock().await.clone();
        let onion = self.onion.lock().await.clone();
        let mut mailbox_ok = false;

        // 1a) 洋葱路径（启用时优先）：多层封装后交给首跳中继，最后一跳落库。
        if onion.enabled && !onion.relays.is_empty() {
            let endpoint = self.transport.endpoint_for(local_id).await?;
            match onion_put(
                &endpoint,
                &onion.relays,
                peer_id,
                &wire.msg_id,
                blob.clone(),
            )
            .await
            {
                Ok(()) => mailbox_ok = true,
                Err(e) => {
                    eprintln!("[app] onion route failed ({e:#}); falling back to direct mailbox")
                }
            }
        }

        // 1b) 直连 mailbox（未启用洋葱或洋葱失败时）。
        if !mailbox_ok && !peers.is_empty() {
            let endpoint = self.transport.endpoint_for(local_id).await?;
            let count = self.mailbox_write_count.load(Ordering::Relaxed);
            match MailboxClient::put_multi(
                &endpoint,
                &peers,
                peer_id,
                &wire.msg_id,
                blob.clone(),
                count,
            )
            .await
            {
                Ok(written) => mailbox_ok = written > 0,
                Err(e) => eprintln!("[app] mailbox PoW failed: {e}"),
            }
        }

        // 2) 直连：生产模式已删除 P2P 投递，只保留单机集成测试的直连通道。
        if self.allow_direct {
            let wire_bytes = serde_json::to_vec(&wire)?;
            if let Err(e) = self.transport.send(local_id, peer_id, &wire_bytes).await {
                if !mailbox_ok {
                    return Err(e);
                }
            }
        } else if !mailbox_ok {
            // 生产模式没有直连兜底：mailbox 未配置或全部失败 = 消息没送达。
            return Err(anyhow!(
                "no delivery path: configure at least one mailbox node (direct P2P has been removed)"
            ));
        }

        // 送达确认（直连成功或有 mailbox 兜底）：提交棘轮推进并持久化。
        {
            let key = (local_id.to_string(), peer_id.to_string());
            let mut ratchets = self.ratchets.lock().await;
            let r = ratchets.get_mut(&key).unwrap();
            r.next();
            let state = r.to_bytes();
            if let Err(e) = self.store.save_ratchet(local_id, peer_id, &state) {
                eprintln!("[app] failed to persist ratchet: {e}");
            }
        }

        let msg = ChatMessage {
            id: msg_id,
            from: local_id.to_string(),
            text: job.text.clone(),
            time: job.utc_time,
        };
        self.append_history(peer_id, msg.clone()).await;
        Ok(msg)
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
}

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
    /// 双棘轮会话缓存：`(local_id, peer_id) -> Ratchet`，随发送/接收推进并
    /// 落盘 `ratchets` 表（重启后续链）。
    ratchets: Arc<Mutex<HashMap<(String, String), crypto::Ratchet>>>,
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

        // 双棘轮会话：从磁盘恢复（需要各专属身份私钥还原 root₀ 与链状态）。
        let identities = store.load_identities()?;
        let mut ratchet_map = HashMap::new();
        for (local_id, peer_id, state) in store.load_ratchets()? {
            let Some(secret_bytes) = identities.get(&local_id) else {
                continue;
            };
            let Ok(secret) = iroh::SecretKey::try_from(secret_bytes.as_slice()) else {
                continue;
            };
            match crypto::Ratchet::from_bytes(&secret, &peer_id, &state) {
                Ok(r) => {
                    ratchet_map.insert((local_id, peer_id), r);
                }
                Err(e) => {
                    eprintln!("[app] discarded incompatible ratchet state for {local_id}: {e}");
                }
            }
        }
        let ratchets = Arc::new(Mutex::new(ratchet_map));
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
            ratchets,
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
        self.ratchets.lock().await.clear();
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
            self.ratchets
                .lock()
                .await
                .remove(&(local_id.clone(), peer_id.to_string()));
            if let Err(e) = self.store.delete_ratchet(&local_id) {
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
                    ratchets: self.ratchets.clone(),
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

    /// 处理传输层收到的信封（wire pack），解密密文 msg 还原为应用消息。
    ///
    /// 直连与 mailbox 两条路径都会产出 `WireMessage`，在此统一解密并
    /// 入库。若发送方尚未登记为联系人则自动登记（单边邀请双向打通），
    /// 并把该消息到达时本端的专属身份（`env.local_id`）绑定给联系人。
    ///
    /// **防冲突**：本端每个专属身份（`local_id`）只能绑定唯一一个对端；
    /// 每个对端也只能绑定唯一一个专属身份。若消息携带的身份已属于别的
    /// 联系人（例如同一邀请被多人连接、或旧身份被重复分享），拒绝处理，
    /// 避免两个联系人共用一个密钥。
    pub async fn handle_incoming(&self, env: IncomingEnvelope) -> Result<Option<ChatMessage>> {
        let wire: WireMessage = serde_json::from_slice(&env.payload)?;
        // 传输层/mailbox 已认证发送方身份，信任其 peer_id。
        let sender = env.peer_id.clone();
        let local_id = env.local_id.clone();

        // —— 防冲突前置检查（绑定关系必须一一对应）——
        {
            let contacts = self.contacts.lock().await;
            // 1) 该专属身份已被另一个对端占用 -> 拒绝。
            if let Some((owner, _)) = contacts.iter().find(|(_, c)| c.local_id == local_id) {
                if owner != &sender {
                    eprintln!(
                        "[app] identity {local_id} already bound to {owner}, rejecting message from {sender}"
                    );
                    return Ok(None);
                }
            }
            // 2) 该对端已绑定到另一个专属身份 -> 拒绝（重复邀请/旧身份泄漏）。
            if let Some(existing) = contacts.get(&sender) {
                if existing.local_id != local_id {
                    eprintln!(
                        "[app] peer {sender} already bound to identity {}, rejecting message via {local_id}",
                        existing.local_id
                    );
                    return Ok(None);
                }
            }
        }

        // 去重前置：同一 msg_id 已入库则不重复解密（防棘轮状态被重复消费）。
        if self
            .history
            .lock()
            .await
            .get(&sender)
            .is_some_and(|conv| conv.iter().any(|m| m.id == wire.msg_id))
        {
            return Ok(None);
        }

        // msg_id 绑定认证发送方和完整密文，拒绝 mailbox 上用可预测
        // (gen,n) 抢占的伪造元数据。
        let expected_id = msg_id_for(&sender, &wire.msg);
        if wire.msg_id != expected_id {
            eprintln!(
                "[app] rejecting message with invalid msg_id {}",
                wire.msg_id
            );
            return Ok(None);
        }

        let secret = self.transport.secret_for(&local_id).await?;
        let plain = {
            let key = (local_id.clone(), sender.clone());
            let mut ratchets = self.ratchets.lock().await;
            if !ratchets.contains_key(&key) {
                // 收到对方首条消息：本端是响应方，用本端 SPK 私钥完成 X3DH。
                let spk = self.transport.spk_for(&local_id).await?;
                ratchets.insert(
                    key.clone(),
                    crypto::Ratchet::new_responder(&secret, &sender, &spk)?,
                );
            }
            ratchets.get_mut(&key).unwrap().decrypt(&wire.msg)?
        };
        let state = {
            let key = (local_id.clone(), sender.clone());
            let ratchets = self.ratchets.lock().await;
            ratchets.get(&key).unwrap().to_bytes()
        };
        if let Err(e) = self.store.save_ratchet(&local_id, &sender, &state) {
            eprintln!("[app] failed to persist ratchet: {e}");
        }
        let plain = privchat_common::unpad_plaintext(&plain);
        let inner: PlainMsg = serde_json::from_slice(&plain)?;

        let msg = ChatMessage {
            id: wire.msg_id,
            from: sender.clone(),
            text: inner.msg_text,
            time: inner.utc_time,
        };
        self.append_history(&sender, msg.clone()).await;

        let mut contacts = self.contacts.lock().await;
        if !contacts.contains_key(&sender) {
            contacts.insert(
                sender.clone(),
                Contact {
                    peer_id: sender.clone(),
                    local_id: local_id.clone(),
                    name: None,
                    ticket: None,
                    // 对端未提供邀请串时拿不到其 SPK；本端仍可继续应答
                    // （会话是对方发起的），但要主动新建会话得先交换邀请。
                    peer_spk: None,
                },
            );
            // 若该身份之前是待绑定邀请身份，现在已绑定。
            self.pending.lock().await.retain(|p| p != &local_id);
        }
        drop(contacts);
        self.persist_contacts().await;

        Ok(Some(msg))
    }
}

/// mailbox 轮询任务持有的最小状态（避免把整个 App 搬进任务）。
struct PollApp {
    transport: Transport,
    mailbox_peers: Arc<Mutex<Vec<String>>>,
    history: Arc<Mutex<HashMap<String, Vec<ChatMessage>>>>,
    contacts: Arc<Mutex<HashMap<String, Contact>>>,
}

impl PollApp {
    async fn poll_mailbox_once(&self, tx: mpsc::UnboundedSender<IncomingEnvelope>) {
        let peers = self.mailbox_peers.lock().await.clone();
        if peers.is_empty() {
            return;
        }
        let contacts = self.contacts.lock().await.clone();

        // 遍历全部联系人的专属身份，逐个拉取各自队列的待收密文。
        for contact in contacts.values() {
            let local_id = contact.local_id.clone();
            let endpoint = match self.transport.endpoint_for(&local_id).await {
                Ok(ep) => ep,
                Err(e) => {
                    eprintln!("[mailbox] no endpoint for {local_id}: {e}");
                    continue;
                }
            };

            for peer in &peers {
                let messages: Vec<StoredMessage> =
                    match MailboxClient::fetch(&endpoint, peer, &local_id).await {
                        Ok(m) => m,
                        Err(e) => {
                            eprintln!("[mailbox] fetch from {peer} failed: {e}");
                            continue;
                        }
                    };
                if messages.is_empty() {
                    continue;
                }

                for stored in &messages {
                    // 只做格式预检（不消耗棘轮状态），真正的解密与入库统一在
                    // handle_incoming 完成。节点侧已「取回即删」（fetch 返回即
                    // 删除并网格广播），这里无需再 ack。队列按本端专属身份
                    // （local_id）分类，只属于该联系人，故发送方即该联系人 peer_id。
                    if !crypto::Ratchet::has_valid_prefix(&stored.msg) {
                        eprintln!("[mailbox] skip non-ratchet message {}", stored.msg_id);
                        continue;
                    }

                    // 已在历史中（可能经直连先到）：跳过，handle_incoming 也会去重。
                    {
                        let hist = self.history.lock().await;
                        if hist
                            .get(&contact.peer_id)
                            .is_some_and(|conv| conv.iter().any(|m| m.id == stored.msg_id))
                        {
                            continue;
                        }
                    }

                    // 重建统一 wire 包，交给 handle_incoming 走与直连相同的路径。
                    let wire = WireMessage {
                        msg_id: stored.msg_id.clone(),
                        to_peer_id: local_id.clone(),
                        msg: stored.msg.clone(),
                    };
                    let payload = match serde_json::to_vec(&wire) {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!("[mailbox] serialize {} failed: {e}", stored.msg_id);
                            continue;
                        }
                    };
                    let env = IncomingEnvelope {
                        local_id: local_id.clone(),
                        peer_id: contact.peer_id.clone(),
                        payload,
                    };
                    let _ = tx.send(env);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
