//! 收件路径：去重 → 校验 msg_id → 多会话尝试解密 → 入库。

use anyhow::{anyhow, Result};

use super::session::{elect_active, session_rows, SessionEntry, SessionRole};
use super::*;

impl App {
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
        let own_ik = secret.public().as_bytes().to_owned();
        let peer_ik = crypto::peer_pub_bytes(&sender)?;
        let spk = self.transport.spk_for(&local_id).await?;
        let plain = {
            let key = (local_id.clone(), sender.clone());
            let mut map = self.sessions.lock().await;
            let entries = map.entry(key.clone()).or_default();

            // 先试主会话，再试其余（并发发起时可能有两条）。
            let mut order: Vec<usize> = (0..entries.len()).collect();
            order.sort_by_key(|&i| !entries[i].active);
            let mut plain = None;
            for i in order {
                let mut trial = entries[i].ratchet.clone();
                if let Ok(p) = trial.decrypt(&wire.msg) {
                    entries[i].ratchet = trial;
                    plain = Some(p);
                    break;
                }
            }

            // 所有会话都解不开：本端作为响应方新建一段（对方是发起方）。
            if plain.is_none() {
                let mut ratchet = crypto::Ratchet::new_responder(&secret, &sender, &spk)?;
                let p = ratchet
                    .decrypt(&wire.msg)
                    .map_err(|e| anyhow!("no session could decrypt message: {e}"))?;
                let ek = crypto::header_ek(&wire.msg)?;
                let id = crypto::session_id(&ek, &own_ik, &peer_ik);
                entries.push(SessionEntry {
                    id,
                    role: SessionRole::Responder,
                    ratchet,
                    active: false,
                });
                elect_active(entries);
                plain = Some(p);
            }

            if let Err(e) = self
                .store
                .save_sessions(&local_id, &sender, &session_rows(entries))
            {
                eprintln!("[app] failed to persist sessions: {e}");
            }
            plain.expect("plain set above")
        };
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
