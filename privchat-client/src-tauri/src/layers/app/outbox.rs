//! 发送队列：加密 → 投递（洋葱/mailbox/直连）→ 送达后提交棘轮。

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::sync::{mpsc, oneshot, watch, Mutex};

use super::session::{session_rows, SessionEntry, SessionMap, SessionRole};
use super::*;

/// 发送 worker 所需的最小状态：仅传需要的字段克隆，避免把整个 `App`
/// （含 send_queues 表，即自身所在映射）搬进任务——否则 worker 与发送
/// 通道互相持有形成自循环，App 被 drop 后 worker 仍存活、Endpoint 端口
/// 无法释放（重启/换库时端口占用）。
#[derive(Clone)]
pub(super) struct SendCtx {
    pub(super) transport: Transport,
    pub(super) store: Arc<crate::layers::store::Store>,
    pub(super) sessions: SessionMap,
    pub(super) mailbox_peers: Arc<Mutex<Vec<String>>>,
    /// 每条离线消息写入的 mailbox 节点数（0 = 全部已配置节点）。
    pub(super) mailbox_write_count: Arc<AtomicUsize>,
    /// 洋葱路由配置（启用时 mailbox 投递走多层转发）。
    pub(super) onion: Arc<Mutex<OnionConfig>>,
    /// 是否保留 P2P 直连投递（仅单机集成测试为 true；生产已删除直连）。
    pub(super) allow_direct: bool,
    pub(super) history: Arc<Mutex<HashMap<String, Vec<ChatMessage>>>>,
    pub(super) contacts: Arc<Mutex<HashMap<String, Contact>>>,
    pub(super) stop: watch::Receiver<bool>,
}

/// 发送队列中的一条待发任务：携带加密所需的最小载荷与应答通道。
pub(super) struct SendJob {
    pub(super) plain_bytes: Vec<u8>,
    pub(super) utc_time: u64,
    pub(super) text: String,
    /// 单条消息的结果回传：worker 处理完（成功/失败）后回填。
    pub(super) reply: oneshot::Sender<Result<ChatMessage>>,
}

/// 单个会话的发送 worker：串行消费队列，逐条加密→投递→确认。
///
/// 每条消息：加密（在 `pending` 暂存推进，不提交）→ mailbox 兜底 →
/// 直连 → 确认送达后 `Ratchet::next` 提交并持久化。若某条消息最终
/// 未送达（无 mailbox 兜底且直连失败），则把队列中剩余消息一并快速
/// 失败（对端已断连，继续发送只会各自等一个超时）。
pub(super) async fn run_send_worker(
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
        let (sid, blob) = {
            let key = (local_id.to_string(), peer_id.to_string());
            let mut map = self.sessions.lock().await;
            let entries = map.entry(key.clone()).or_default();
            // 没有已建立的主会话：新建一段发起方会话（需要对方 SPK，邀请串携带）。
            if !entries
                .iter()
                .any(|e| e.active && e.ratchet.is_established())
            {
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
                let ratchet = crypto::Ratchet::new_initiator(&secret, peer_id, &peer_spk)?;
                let ek = ratchet
                    .own_ek()
                    .ok_or_else(|| anyhow!("initiator session has no EK"))?;
                let id = crypto::session_id(
                    &ek,
                    secret.public().as_bytes(),
                    &crypto::peer_pub_bytes(peer_id)?,
                );
                entries.push(SessionEntry {
                    id,
                    role: SessionRole::Initiator,
                    ratchet,
                    active: false,
                });
                elect_active(entries);
            }
            let idx = entries
                .iter()
                .position(|e| e.active)
                .ok_or_else(|| anyhow!("no active session"))?;
            let blob = entries[idx].ratchet.encrypt(&job.plain_bytes)?;
            (entries[idx].id.clone(), blob)
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
            let mut map = self.sessions.lock().await;
            if let Some(entries) = map.get_mut(&key) {
                if let Some(entry) = entries.iter_mut().find(|e| e.id == sid) {
                    entry.ratchet.next();
                }
                if let Err(e) = self
                    .store
                    .save_sessions(local_id, peer_id, &session_rows(entries))
                {
                    eprintln!("[app] failed to persist sessions: {e}");
                }
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
