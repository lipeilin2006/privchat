//! Layer 1.5 · Mailbox 客户端 (离线消息代理)
//!
//! 用一条临时拨号身份连信箱节点：ping 探活，或者把已封好的洋葱包
//! 送到第一跳并读回响应。队列请求本身由 `links` 直接用 `privchat-common`
//! 的 `send_request` 发，这里不再重复封装一套。

use anyhow::{anyhow, Result};
use iroh::Endpoint;
use privchat_common::{send_request, MailboxRequest, MailboxResponse};
use privchat_onion::ONION_ALPN;

/// Mailbox 客户端：无状态辅助函数，所有操作显式接收「身份 Endpoint」。
pub struct MailboxClient;

impl MailboxClient {
    /// 检查 mailbox 是否可达，不读取也不删除任何消息。
    pub async fn ping(endpoint: &Endpoint, mailbox: &str) -> Result<()> {
        let response = Self::call(endpoint, mailbox, &MailboxRequest::ping()).await?;
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

    /// 走洋葱中继发一个请求：包已经按路径封好，这里只负责送到第一跳并读回响应。
    /// 响应对中继是黑盒，它们只转发字节，不解包。
    pub async fn request_via_onion(
        endpoint: &Endpoint,
        first_hop: &str,
        packet: Vec<u8>,
    ) -> Result<MailboxResponse> {
        let id: iroh::EndpointId = first_hop
            .parse()
            .map_err(|_| anyhow!("invalid onion first hop: {first_hop}"))?;
        let conn = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            endpoint.connect(iroh::EndpointAddr::new(id), ONION_ALPN),
        )
        .await
        .map_err(|_| anyhow!("connect onion relay timed out"))??;
        let (mut send, mut recv) = conn.open_bi().await?;
        send.write_all(&packet).await?;
        send.finish()?;
        let bytes = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            recv.read_to_end(32 * 1024 * 1024),
        )
        .await
        .map_err(|_| anyhow!("waiting onion response timed out"))??;
        serde_json::from_slice(&bytes).map_err(|e| anyhow!("bad onion response: {e}"))
    }
}
