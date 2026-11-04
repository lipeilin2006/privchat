//! mailbox 轮询：按联系人队列逐条拉取，预处理后投给收件路径。

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::sync::Mutex;

use super::*;

/// mailbox 轮询任务持有的最小状态（避免把整个 App 搬进任务）。
pub(super) struct PollApp {
    pub(super) transport: Transport,
    pub(super) mailbox_peers: Arc<Mutex<Vec<String>>>,
    pub(super) history: Arc<Mutex<HashMap<String, Vec<ChatMessage>>>>,
    pub(super) contacts: Arc<Mutex<HashMap<String, Contact>>>,
}

impl PollApp {
    pub(super) async fn poll_mailbox_once(&self, tx: mpsc::UnboundedSender<IncomingEnvelope>) {
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
