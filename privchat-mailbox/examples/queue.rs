//! 队列自检：对一个 mailbox 节点跑一遍 create → send → get → delete。
//!
//!   cargo run -p privchat-mailbox --example queue -- <mailbox_peer_id>
//!
//! 全流程用随机生成的 sender/owner 密钥，不碰任何真实数据，
//! 适合部署完验证节点是否正常工作。

use anyhow::{anyhow, Result};
use ed25519_dalek::{Signer, SigningKey};
use privchat_mailbox::{make_endpoint, send_request, MailboxRequest};
use rand_core::OsRng;
use rand_core::RngCore;

const DOMAIN_SEND: &[u8] = b"privchat/queue/send/v1";
const DOMAIN_GET: &[u8] = b"privchat/queue/get/v1";
const DOMAIN_DELETE: &[u8] = b"privchat/queue/delete/v1";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sign(domain: &[u8], queue: &[u8; 16], payload: Option<&[u8]>, key: &SigningKey) -> String {
    let mut msg = domain.to_vec();
    msg.extend_from_slice(queue);
    if let Some(payload) = payload {
        msg.extend_from_slice(payload);
    }
    hex(&key.sign(&msg).to_bytes())
}

#[tokio::main]
async fn main() -> Result<()> {
    let peer_id = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow!("usage: queue <mailbox_peer_id>"))?;

    let sender = SigningKey::from_bytes(&random32());
    let owner = SigningKey::from_bytes(&random32());
    let mut queue = [0u8; 16];
    OsRng.fill_bytes(&mut queue);
    let queue_hex = hex(&queue);

    let endpoint = make_endpoint(iroh::SecretKey::generate()).await?;
    println!("[queue] node={peer_id} queue={queue_hex}");

    let create = MailboxRequest::queue_create(
        &queue_hex,
        &hex(sender.verifying_key().as_bytes()),
        &hex(owner.verifying_key().as_bytes()),
    );
    let resp = send_request(&endpoint, &peer_id, &create).await?;
    println!("create => ok={} err={:?}", resp.ok, resp.error);
    if !resp.ok {
        return Err(anyhow!("create failed"));
    }

    for i in 0..2 {
        let payload = format!("hello-{i}").into_bytes();
        let sig = sign(DOMAIN_SEND, &queue, Some(&payload), &sender);
        let req = MailboxRequest::queue_send(&queue_hex, payload, &sig);
        let resp = send_request(&endpoint, &peer_id, &req).await?;
        println!("send[{i}] => ok={} err={:?}", resp.ok, resp.error);
    }

    let sig = sign(DOMAIN_GET, &queue, None, &owner);
    let resp = send_request(
        &endpoint,
        &peer_id,
        &MailboxRequest::queue_get(&queue_hex, &sig),
    )
    .await?;
    let msgs = resp.messages.unwrap_or_default();
    println!("get => ok={} count={}", resp.ok, msgs.len());
    for m in &msgs {
        println!("  {} -> {:?}", m.msg_id, String::from_utf8_lossy(&m.msg));
    }

    // 取回即删：再取一次应该是空的。
    let sig = sign(DOMAIN_GET, &queue, None, &owner);
    let again = send_request(
        &endpoint,
        &peer_id,
        &MailboxRequest::queue_get(&queue_hex, &sig),
    )
    .await?;
    println!(
        "get-again => count={}",
        again.messages.unwrap_or_default().len()
    );

    let sig = sign(DOMAIN_DELETE, &queue, None, &owner);
    let resp = send_request(
        &endpoint,
        &peer_id,
        &MailboxRequest::queue_delete(&queue_hex, &sig),
    )
    .await?;
    println!("delete => ok={} err={:?}", resp.ok, resp.error);

    endpoint.close().await;
    Ok(())
}

fn random32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}
