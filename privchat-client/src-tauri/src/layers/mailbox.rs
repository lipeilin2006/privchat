//! Layer 1.5 · Mailbox 客户端 (离线消息代理)
//!
//! 复用聊天身份的 iroh Endpoint（拨号时指定 mailbox ALPN），负责与 mailbox
//! 节点通信：把加密后的离线消息 PUT 上去、FETCH 本端待收密文、ACK 确认删除。
//!
//! mailbox 节点与聊天直连是两套独立的 ALPN，互不干扰。每个请求一条
//! QUIC bi-stream：写入 JSON 请求，读回 JSON 响应。
//!
//! 所有操作都以「身份 Endpoint」为参数：调用方传入某联系人的专属身份
//! Endpoint，令 mailbox 节点看到的 TLS 身份是**该联系人的专属身份**而非
//! 全局主身份，避免 mailbox 节点跨联系人关联本端。
//!
//! wire 协议（请求/响应/常量/PoW）统一由 `privchat-common` 提供，本层只
//! 保留客户端操作封装，避免与 mailbox 节点重复维护协议。

#[cfg(test)]
use std::path::PathBuf;

use anyhow::{anyhow, Result};
#[cfg(test)]
use iroh::endpoint::presets;
#[cfg(test)]
use iroh::protocol::Router;
use iroh::Endpoint;
#[cfg(test)]
use iroh::SecretKey;
#[cfg(test)]
use privchat_common::ALPN;
use privchat_common::{find_pow, send_request, MailboxRequest, MailboxResponse};
use tokio::task::JoinSet;

pub use privchat_common::StoredMessage;

/// Mailbox 客户端：无状态辅助函数，所有操作显式接收「身份 Endpoint」。
pub struct MailboxClient;

impl MailboxClient {
    /// 检查 mailbox 是否可达，不读取也不删除任何消息。
    pub async fn ping(endpoint: &Endpoint, mailbox: &str) -> Result<()> {
        let response = Self::call(
            endpoint,
            mailbox,
            &MailboxRequest {
                op: privchat_common::Op::Ping,
                to: None,
                for_peer: None,
                id: None,
                ids: None,
                payload: None,
                nonce: None,
                msg: None,
                queue: None,
                sender_auth: None,
                owner_auth: None,
                sig: None,
            },
        )
        .await?;
        if response.ok {
            Ok(())
        } else {
            Err(anyhow!(
                "mailbox ping failed: {}",
                response.error.unwrap_or_default()
            ))
        }
    }
    /// 创建独立端点（仅测试/独立进程使用）：复用 data_dir/secret.key 身份。
    #[cfg(test)]
    pub async fn start(data_dir: PathBuf) -> Result<Endpoint> {
        let secret_path = data_dir.join("secret.key");
        let secret_key = if let Ok(bytes) = std::fs::read(&secret_path) {
            SecretKey::try_from(bytes.as_slice())?
        } else {
            let key = SecretKey::generate();
            std::fs::write(&secret_path, key.to_bytes())?;
            key
        };
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(secret_key)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await?;
        let _router = Router::builder(endpoint.clone()).spawn();
        // 等待上线（联系上 relay），确保可被拨号/可拨号。加限时防 relay
        // 不可达时挂死（与 transport::build_identity 一致）。
        let _ = tokio::time::timeout(std::time::Duration::from_secs(8), endpoint.online()).await;
        Ok(endpoint)
    }

    /// 向 mailbox 节点发一个请求，返回响应。用传入的身份 Endpoint 拨号，
    /// 让 mailbox 节点看到的 TLS 身份为该联系人专属身份。
    async fn call(
        endpoint: &Endpoint,
        mailbox: &str,
        req: &MailboxRequest,
    ) -> Result<MailboxResponse> {
        send_request(endpoint, mailbox, req).await
    }

    /// 上传一条密文邮件。先计算 PoW nonce（防垃圾），随请求提交。
    /// 发送方由拨号 Endpoint 的 TLS 身份决定，无需显式传 from。
    #[cfg(test)]
    pub async fn put(
        endpoint: &Endpoint,
        mailbox: &str,
        to: &str,
        id: &str,
        payload: Vec<u8>,
    ) -> Result<()> {
        let nonce = Self::pow_nonce(to, &payload).await?;
        Self::put_with_nonce(endpoint, mailbox, to, id, payload, nonce).await
    }

    /// 在独立线程算 PoW，避免阻塞 IO 任务。
    async fn pow_nonce(to: &str, payload: &[u8]) -> Result<u64> {
        let to_owned = to.to_string();
        let payload_owned = payload.to_vec();
        tokio::task::spawn_blocking(move || find_pow(&to_owned, &payload_owned))
            .await
            .map_err(|e| anyhow!("pow task failed: {e}"))
    }

    /// 上传一条密文邮件（复用已算好的 nonce）。
    async fn put_with_nonce(
        endpoint: &Endpoint,
        mailbox: &str,
        to: &str,
        id: &str,
        payload: Vec<u8>,
        nonce: u64,
    ) -> Result<()> {
        let resp = Self::call(
            endpoint,
            mailbox,
            &MailboxRequest::put(to, id, payload, nonce),
        )
        .await?;
        if resp.ok {
            Ok(())
        } else {
            Err(anyhow!(
                "mailbox put failed: {}",
                resp.error.unwrap_or_default()
            ))
        }
    }

    /// 把同一条密文投放到多个 mailbox 节点（多副本冗余）。
    ///
    /// PoW nonce 只算一次、全部节点复用（同一 `(to, payload)` 的 nonce
    /// 相同，各节点均可验证）。最多同时请求 `count` 个节点，失败时再用
    /// 后续节点补位，直到达到目标副本数或耗尽节点；`count = 0` 表示并发
    /// 投到全部已配置节点。返回成功投放的节点数。
    pub async fn put_multi(
        endpoint: &Endpoint,
        mailboxes: &[String],
        to: &str,
        id: &str,
        payload: Vec<u8>,
        count: usize,
    ) -> Result<usize> {
        if mailboxes.is_empty() {
            return Ok(0);
        }
        let target = if count == 0 {
            mailboxes.len()
        } else {
            count.min(mailboxes.len())
        };
        let nonce = Self::pow_nonce(to, &payload).await?;
        let mut remaining = mailboxes.iter().cloned();
        let mut requests = JoinSet::new();
        for _ in 0..target {
            if let Some(mailbox) = remaining.next() {
                Self::spawn_put(
                    &mut requests,
                    endpoint.clone(),
                    mailbox,
                    to.to_string(),
                    id.to_string(),
                    payload.clone(),
                    nonce,
                );
            }
        }

        let mut ok = 0;
        while let Some(result) = requests.join_next().await {
            let succeeded = match result {
                Ok((_mailbox, Ok(()))) => {
                    ok += 1;
                    true
                }
                Ok((mailbox, Err(e))) => {
                    eprintln!("[mailbox] put to {mailbox} failed: {e}");
                    false
                }
                Err(e) => {
                    eprintln!("[mailbox] put task failed: {e}");
                    false
                }
            };
            if ok >= target {
                requests.abort_all();
                break;
            }
            if !succeeded {
                if let Some(mailbox) = remaining.next() {
                    Self::spawn_put(
                        &mut requests,
                        endpoint.clone(),
                        mailbox,
                        to.to_string(),
                        id.to_string(),
                        payload.clone(),
                        nonce,
                    );
                }
            }
        }
        Ok(ok)
    }

    fn spawn_put(
        requests: &mut JoinSet<(String, Result<()>)>,
        endpoint: Endpoint,
        mailbox: String,
        to: String,
        id: String,
        payload: Vec<u8>,
        nonce: u64,
    ) {
        requests.spawn(async move {
            let result = Self::put_with_nonce(&endpoint, &mailbox, &to, &id, payload, nonce).await;
            (mailbox, result)
        });
    }

    /// 拉取本端全部待收密文（节点侧「取回即删」并广播删除同步）。
    pub async fn fetch(endpoint: &Endpoint, mailbox: &str, me: &str) -> Result<Vec<StoredMessage>> {
        let resp = Self::call(endpoint, mailbox, &MailboxRequest::fetch(me)).await?;
        if resp.ok {
            Ok(resp.messages.unwrap_or_default())
        } else {
            Err(anyhow!(
                "mailbox fetch failed: {}",
                resp.error.unwrap_or_default()
            ))
        }
    }
    // ---- 单向队列（SimpleX 式） ----

    /// 在 mailbox 上创建接收队列（登记 sender / owner 两把公钥）。
    pub async fn queue_create(
        endpoint: &Endpoint,
        mailbox: &str,
        queue: &str,
        sender_auth: &str,
        owner_auth: &str,
    ) -> Result<()> {
        let resp = Self::call(
            endpoint,
            mailbox,
            &MailboxRequest::queue_create(queue, sender_auth, owner_auth),
        )
        .await?;
        if resp.ok {
            Ok(())
        } else {
            Err(anyhow!(
                "queue_create failed: {}",
                resp.error.unwrap_or_default()
            ))
        }
    }

    /// 向队列投递一条密文（`sig` 覆盖 domain || queue || payload）。
    pub async fn queue_send(
        endpoint: &Endpoint,
        mailbox: &str,
        queue: &str,
        payload: Vec<u8>,
        sig: &str,
    ) -> Result<()> {
        let resp = Self::call(
            endpoint,
            mailbox,
            &MailboxRequest::queue_send(queue, payload, sig),
        )
        .await?;
        if resp.ok {
            Ok(())
        } else {
            Err(anyhow!(
                "queue_send failed: {}",
                resp.error.unwrap_or_default()
            ))
        }
    }

    /// 取走队列里的全部消息（owner 签名）。
    pub async fn queue_get(
        endpoint: &Endpoint,
        mailbox: &str,
        queue: &str,
        sig: &str,
    ) -> Result<Vec<StoredMessage>> {
        let resp = Self::call(endpoint, mailbox, &MailboxRequest::queue_get(queue, sig)).await?;
        if resp.ok {
            Ok(resp.messages.unwrap_or_default())
        } else {
            Err(anyhow!(
                "queue_get failed: {}",
                resp.error.unwrap_or_default()
            ))
        }
    }

    /// 删除队列（owner 签名）。
    pub async fn queue_delete(
        endpoint: &Endpoint,
        mailbox: &str,
        queue: &str,
        sig: &str,
    ) -> Result<()> {
        let resp = Self::call(endpoint, mailbox, &MailboxRequest::queue_delete(queue, sig)).await?;
        if resp.ok {
            Ok(())
        } else {
            Err(anyhow!(
                "queue_delete failed: {}",
                resp.error.unwrap_or_default()
            ))
        }
    }
}
