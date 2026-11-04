//! 端到端探测：把一个 ping 请求包进洋葱，经中继送到信箱。
//!
//!   cargo run -p privchat-relay --example onion_probe -- <relay_peer_id> <mailbox_peer_id>
//!
//! 验证的是整条链路：客户端封包 → 中继剥层转发 → 信箱终点处理 → 响应原路回来。

use anyhow::{anyhow, Result};
use privchat_common::{MailboxRequest, MailboxResponse};
use privchat_onion::{wrap, ONION_ALPN, RESPONSE_MAX};

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let relay = args
        .next()
        .ok_or_else(|| anyhow!("usage: onion_probe <relay> <mailbox>"))?;
    let mailbox = args
        .next()
        .ok_or_else(|| anyhow!("usage: onion_probe <relay> <mailbox>"))?;

    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(iroh::SecretKey::generate())
        .bind()
        .await?;

    let body = serde_json::to_vec(&MailboxRequest::ping())?;
    let packet = wrap(&[relay.clone(), mailbox.clone()], &body)?;
    println!(
        "[probe] relay={relay}\n[probe] mailbox={mailbox}\n[probe] packet={}B",
        packet.len()
    );

    let id: iroh::EndpointId = relay.parse()?;
    let started = std::time::Instant::now();
    let conn = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        endpoint.connect(iroh::EndpointAddr::new(id), ONION_ALPN),
    )
    .await
    .map_err(|_| anyhow!("connect relay timed out"))??;
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(&packet).await?;
    send.finish()?;
    let bytes = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        recv.read_to_end(RESPONSE_MAX),
    )
    .await
    .map_err(|_| anyhow!("waiting response timed out"))??;
    let resp: MailboxResponse =
        serde_json::from_slice(&bytes).map_err(|e| anyhow!("bad response: {e}"))?;
    println!(
        "[probe] ok={} error={:?} rtt={}ms",
        resp.ok,
        resp.error,
        started.elapsed().as_millis()
    );
    endpoint.close().await;
    Ok(())
}
