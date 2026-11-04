//! 命令行测试客户端：ping 节点，或用 owner 身份取走/删除一条队列。
//!
//! 队列操作用例一般由客户端代码覆盖，这里只留最小验证入口：
//!   cargo run --example client -- <mailbox_peer_id> ping

use anyhow::{anyhow, Result};
use privchat_mailbox::{make_endpoint, send_request, MailboxRequest};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        return Err(anyhow!("usage: client <mailbox_peer_id> ping"));
    }
    let peer_id = &args[1];
    let op = &args[2];

    let endpoint = make_endpoint(iroh::SecretKey::generate()).await?;
    eprintln!("[client] connecting to {peer_id} op={op}");

    let req = match op.as_str() {
        "ping" => MailboxRequest::ping(),
        other => return Err(anyhow!("unknown op: {other} (only ping)")),
    };

    match send_request(&endpoint, peer_id, &req).await {
        Ok(resp) => println!("{op}  => ok={} error={:?}", resp.ok, resp.error),
        Err(e) => println!("{op}  => ERROR: {e:#}"),
    }
    endpoint.close().await;
    Ok(())
}
