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
use privchat_common::{send_request, MailboxRequest, MailboxResponse};

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
