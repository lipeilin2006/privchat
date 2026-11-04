//! Layer 1.5 · Mailbox 客户端 (离线消息代理)
//!
//! 用一条临时拨号身份连 mailbox 节点，执行队列操作：
//! create / send / get / delete / ping。每个请求一条 QUIC bi-stream：
//! 写入 JSON 请求，读回 JSON 响应。队列权限靠 Ed25519 签名，不依赖 TLS 身份。
//!
//! wire 协议（请求/响应/常量/PoW）统一由 `privchat-common` 提供，本层只
//! 保留客户端操作封装，避免与 mailbox 节点重复维护协议。

use anyhow::{anyhow, Result};
use iroh::Endpoint;
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
    /// 向 mailbox 节点发一个请求，返回响应。
    /// 用传入的临时身份 Endpoint 拨号，节点看到的 TLS 身份随连接变化。
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
