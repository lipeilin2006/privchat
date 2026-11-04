//! PrivChat Mailbox —— 离线消息缓存节点（可组网同步）
//!
//! 纯存储节点：不参与任何会话加密。客户端先做应用层加密（双棘轮，见
//! client 的 `crypto::Ratchet`），再把密文 `payload` 交给本节点暂存。
//! 本节点只按「接收方 peer_id」分类存取、按消息 ID 排序与删除，永不接触明文。
//!
//! ## 取回即删 + TTL
//! `fetch` 按 `msg_id` 升序返回该接收方队列的全部密文，返回后立即从本节点
//! 删除，并向 peer 广播 `sync_ack` 让网格同步删除其他副本。msg_id 由发送方
//! 从加密头的 `(gen, n)`（逻辑发送序）派生，故按 msg_id 排序即等于棘轮
//! 消息顺序；不含时间戳，不泄露收发时间。
//! 消息最长保留时间（TTL）可配置，到期由后台任务清除：
//! - 环境变量 `PRIVCHAT_MAILBOX_TTL_SECS`（秒，0 = 永不过期），或
//! - `data_dir/config.json` 的 `{"ttl_secs": <秒>}`；缺省 7 天。
//!
//! ## 组网同步（多跳、无环路）
//! 每个 mailbox 通过配置知道若干其他 mailbox 节点（可全连通、可链式/环状）。
//! 收到客户端消息后向所有 peer 广播 `sync`；收到 `ack`/`fetch` 删除后广播
//! `sync_ack`。广播消息携带完整消息，接收方按 msg_id 幂等去重，**仅在真正
//! 新增/删除时继续转发**（`INSERT OR IGNORE` 主键幂等保证每条消息每节点
//! 至多处理一次），因此多跳链路（client0→mb0→mb1→mb2→client1）可传播到底，
//! 而环状拓扑中节点第二次收到同一条消息时不再转发，环路/风暴从结构上被截断。
//! 客户端连任意一个 mailbox 节点都能 fetch 到全部待收消息。
//!
//! peer 配置（二选一，环境变量优先）：
//! - `PRIVCHAT_MAILBOX_PEERS="<peer_id>,<peer_id>,..."`，或
//! - `data_dir/mailboxes.json` = `["<peer_id>", ...]`

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::SecretKey;

use privchat_common::{MailboxRequest, MailboxResponse, Op, StoredMessage, ALPN, MAX_PAYLOAD};
use privchat_onion::{peel, ONION_ALPN};

use crate::store::MailboxStore;

/// 连接处理循环：读一个 bi-stream，解析请求，返回响应。
#[derive(Debug, Clone)]
struct MailboxHandler {
    store: MailboxStore,
}

impl ProtocolHandler for MailboxHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        // 拨号方的 TLS 身份：fetch 必须用自己身份拉自己的队列（防他人
        // 取回即删式 DoS）；put/sync 不校验（任意发送方 + PoW 防垃圾）。
        let remote_id = connection.remote_id().to_string();
        loop {
            let (mut send, mut recv) = match connection.accept_bi().await {
                Ok(bi) => bi,
                Err(_) => break,
            };

            let payload = match recv.read_to_end(MAX_PAYLOAD).await {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("[mailbox] accept_bi read failed: {e:#}");
                    continue;
                }
            };

            let response = handle_request(self, &remote_id, &payload).await;
            let bytes = serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec());
            let _ = send.write_all(&bytes).await;
            let _ = send.finish();
        }
        Ok(())
    }
}

/// 洋葱中继处理器：剥离一层后转发，或作为终点把最内层请求交给 mailbox 处理。
#[derive(Debug, Clone)]
struct OnionHandler {
    mailbox: MailboxHandler,
    secret: SecretKey,
    endpoint: iroh::Endpoint,
    /// 允许把剥离后的包继续转发（中继角色）
    allow_forward: bool,
    /// 允许作为终点把最内层请求交给 mailbox（存储角色）
    allow_terminal: bool,
    /// 允许转发的下一跳白名单（None = 不限制）
    onion_allow: Option<Arc<Vec<String>>>,
}

impl ProtocolHandler for OnionHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote = connection.remote_id().to_string();
        let (mut send, mut recv) = match connection.accept_bi().await {
            Ok(bi) => bi,
            Err(_) => return Ok(()),
        };
        let packet = match recv.read_to_end(ONION_PACKET_MAX).await {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("[onion] read failed: {error:#}");
                return Ok(());
            }
        };
        match peel(&self.secret, &packet) {
            Ok((Some(next), inner)) => {
                if !self.allow_forward {
                    let response = MailboxResponse {
                        ok: false,
                        error: Some("this node is mailbox-only: refusing to relay".into()),
                        messages: None,
                    };
                    let _ = send
                        .write_all(&serde_json::to_vec(&response).unwrap_or_default())
                        .await;
                    let _ = send.finish();
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    return Ok(());
                }
                if let Some(allow) = &self.onion_allow {
                    if !allow.iter().any(|p| p == &next) {
                        let response = MailboxResponse {
                            ok: false,
                            error: Some("next hop is not in the onion allowlist".into()),
                            messages: None,
                        };
                        let _ = send
                            .write_all(&serde_json::to_vec(&response).unwrap_or_default())
                            .await;
                        let _ = send.finish();
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        return Ok(());
                    }
                }
                eprintln!(
                    "[onion] relay from {}: forwarding {}B to {}",
                    short_id(&remote),
                    inner.len(),
                    short_id(&next)
                );
                let endpoint = self.endpoint.clone();
                let forwarded = forward_onion(&endpoint, &next, inner).await;
                eprintln!(
                    "[onion] forward result: {}",
                    match &forwarded {
                        Ok(resp) => format!("ok={}", resp.ok),
                        Err(error) => format!("err={error:#}"),
                    }
                );
                let response = match forwarded {
                    Ok(resp) if resp.ok => MailboxResponse {
                        ok: true,
                        error: None,
                        messages: None,
                    },
                    Ok(resp) => MailboxResponse {
                        ok: false,
                        error: Some(format!(
                            "downstream {next} rejected: {}",
                            resp.error.unwrap_or_default()
                        )),
                        messages: None,
                    },
                    Err(error) => MailboxResponse {
                        ok: false,
                        error: Some(format!("relay to {next} failed: {error:#}")),
                        messages: None,
                    },
                };
                let wrote = send
                    .write_all(&serde_json::to_vec(&response).unwrap_or_default())
                    .await;
                eprintln!("[onion] response write ok={}", wrote.is_ok());
                let _ = send.finish();
            }
            Ok((None, inner)) => {
                if !self.allow_terminal {
                    let response = MailboxResponse {
                        ok: false,
                        error: Some("this node is relay-only: refusing terminal delivery".into()),
                        messages: None,
                    };
                    let _ = send
                        .write_all(&serde_json::to_vec(&response).unwrap_or_default())
                        .await;
                    let _ = send.finish();
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    return Ok(());
                }
                // 终点：只允许匿名投递（put），fetch 需要真实身份队列认证。
                let response = handle_request(&self.mailbox, &remote, &inner).await;
                let _ = send
                    .write_all(&serde_json::to_vec(&response).unwrap_or_default())
                    .await;
                let _ = send.finish();
            }
            Err(error) => {
                eprintln!("[onion] peel failed from {remote}: {error:#}");
                let response = MailboxResponse {
                    ok: false,
                    error: Some(format!("onion peel failed: {error:#}")),
                    messages: None,
                };
                let _ = send
                    .write_all(&serde_json::to_vec(&response).unwrap_or_default())
                    .await;
                let _ = send.finish();
            }
        }
        // 给对端一点时间读走最后一段响应再关闭连接（QUIC 关闭会丢弃
        // 尚未被读取的流数据，实测直接返回会导致客户端读到 connection lost）。
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        Ok(())
    }
}

/// 把剩余洋葱包转发给下一跳（限制超时，避免慢节点拖死中继）。
async fn forward_onion(
    endpoint: &iroh::Endpoint,
    next: &str,
    inner: Vec<u8>,
) -> Result<MailboxResponse> {
    let id: iroh::EndpointId = next
        .parse()
        .map_err(|_| anyhow!("invalid next hop: {next}"))?;
    let conn = tokio::time::timeout(
        std::time::Duration::from_secs(90),
        endpoint.connect(iroh::EndpointAddr::new(id), ONION_ALPN),
    )
    .await
    .map_err(|_| anyhow!("connect {next} timed out"))??;
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(&inner).await?;
    send.finish()?;
    let bytes = tokio::time::timeout(std::time::Duration::from_secs(90), recv.read_to_end(4096))
        .await
        .map_err(|_| anyhow!("waiting {next} response timed out"))??;
    let response: MailboxResponse =
        serde_json::from_slice(&bytes).map_err(|e| anyhow!("bad response from {next}: {e}"))?;
    Ok(response)
}

async fn handle_request(
    handler: &MailboxHandler,
    remote_id: &str,
    payload: &[u8],
) -> MailboxResponse {
    let req: MailboxRequest = match serde_json::from_slice(payload) {
        Ok(r) => r,
        Err(e) => return err(&format!("bad request: {e}")),
    };
    let _ = remote_id;
    match req.op {
        Op::Ping => ok(),
        Op::QueueCreate => handle_queue_create(handler, req).await,
        Op::QueueSend => handle_queue_send(handler, req).await,
        Op::QueueGet => handle_queue_get(handler, req).await,
        Op::QueueDelete => handle_queue_delete(handler, req).await,
    }
}

/// 队列操作的签名域分隔。
const QUEUE_SEND_DOMAIN: &[u8] = b"privchat/queue/send/v1";

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for i in (0..bytes.len()).step_by(2) {
        out.push((hex_val(bytes[i])? << 4) | hex_val(bytes[i + 1])?);
    }
    Some(out)
}

/// 用 Ed25519 公钥（32B）验签；`msg` 由调用方拼好域分隔。
/// 队列 id 必须是 32 位 hex（16 字节），签名按原始字节算。
fn queue_bytes(q: &str) -> Option<[u8; 16]> {
    if q.len() != 32 {
        return None;
    }
    hex_decode(q)?.as_slice().try_into().ok()
}

fn verify_sig(pubkey: &[u8], msg: &[u8], sig_hex: &str) -> bool {
    let Ok(pk) = <[u8; 32]>::try_from(pubkey) else {
        return false;
    };
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    let Some(sig_bytes) = hex_decode(sig_hex) else {
        return false;
    };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    vk.verify_strict(msg, &sig).is_ok()
}

/// 创建接收队列：先到先得，已存在直接拒绝。
async fn handle_queue_create(handler: &MailboxHandler, req: MailboxRequest) -> MailboxResponse {
    let (Some(queue), Some(sender_auth), Some(owner_auth)) =
        (req.queue, req.sender_auth, req.owner_auth)
    else {
        return err("queue_create missing fields");
    };
    if queue_bytes(&queue).is_none() || sender_auth.len() != 64 || owner_auth.len() != 64 {
        return err("queue_create: bad field length");
    }
    let (Some(sender), Some(owner)) = (hex_decode(&sender_auth), hex_decode(&owner_auth)) else {
        return err("queue_create: bad hex");
    };
    match handler
        .store
        .create_queue(&queue, &sender, &owner, now_ms())
        .await
    {
        Ok(true) => ok(),
        Ok(false) => err("queue exists"),
        Err(e) => err(&format!("queue_create failed: {e}")),
    }
}

/// 投递：发送方必须用队列登记的 sender key 对 `domain || queue || payload` 签名。
async fn handle_queue_send(handler: &MailboxHandler, req: MailboxRequest) -> MailboxResponse {
    let (Some(queue), Some(payload), Some(sig)) = (req.queue, req.payload, req.sig) else {
        return err("queue_send missing fields");
    };
    let Some(qid) = queue_bytes(&queue) else {
        return err("queue_send: bad queue id");
    };
    let Some((sender_auth, _)) = handler.store.queue_auth(&queue).await.unwrap_or(None) else {
        return err("queue not found");
    };
    let mut msg = QUEUE_SEND_DOMAIN.to_vec();
    msg.extend_from_slice(&qid);
    msg.extend_from_slice(&payload);
    if !verify_sig(&sender_auth, &msg, &sig) {
        return err("queue_send: bad signature");
    }
    match handler.store.push_queue(&queue, &payload, now_ms()).await {
        Ok(_) => ok(),
        Err(e) => err(&format!("queue_send failed: {e}")),
    }
}

/// 取走：只有 owner key 能取（签名覆盖 `domain || queue`）。
async fn handle_queue_get(handler: &MailboxHandler, req: MailboxRequest) -> MailboxResponse {
    let (Some(queue), Some(sig)) = (req.queue, req.sig) else {
        return err("queue_get missing fields");
    };
    let Some(qid) = queue_bytes(&queue) else {
        return err("queue_get: bad queue id");
    };
    let Some((_, owner_auth)) = handler.store.queue_auth(&queue).await.unwrap_or(None) else {
        return err("queue not found");
    };
    let mut msg = b"privchat/queue/get/v1".to_vec();
    msg.extend_from_slice(&qid);
    if !verify_sig(&owner_auth, &msg, &sig) {
        return err("queue_get: bad signature");
    }
    match handler.store.take_queue(&queue).await {
        Ok(rows) => MailboxResponse {
            ok: true,
            error: None,
            messages: Some(
                rows.into_iter()
                    .map(|(seq, payload)| StoredMessage {
                        msg_id: seq.to_string(),
                        to_peer_id: queue.clone(),
                        msg: payload,
                    })
                    .collect(),
            ),
        },
        Err(e) => err(&format!("queue_get failed: {e}")),
    }
}

/// 删除队列：owner key 签名。
async fn handle_queue_delete(handler: &MailboxHandler, req: MailboxRequest) -> MailboxResponse {
    let (Some(queue), Some(sig)) = (req.queue, req.sig) else {
        return err("queue_delete missing fields");
    };
    let Some(qid) = queue_bytes(&queue) else {
        return err("queue_delete: bad queue id");
    };
    let Some((_, owner_auth)) = handler.store.queue_auth(&queue).await.unwrap_or(None) else {
        return err("queue not found");
    };
    let mut msg = b"privchat/queue/delete/v1".to_vec();
    msg.extend_from_slice(&qid);
    if !verify_sig(&owner_auth, &msg, &sig) {
        return err("queue_delete: bad signature");
    }
    match handler.store.delete_queue(&queue).await {
        Ok(_) => ok(),
        Err(e) => err(&format!("queue_delete failed: {e}")),
    }
}

/// 本地操作完成后在后台向所有 peer mailbox 并发广播，避免阻塞客户端响应。
/// 洋葱转发白名单：`PRIVCHAT_MAILBOX_ONION_PEERS="id1,id2"`，未设置则不限制。
fn load_onion_allowlist() -> Option<Arc<Vec<String>>> {
    let raw = std::env::var("PRIVCHAT_MAILBOX_ONION_PEERS").ok()?;
    let list: Vec<String> = raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| s.len() == 64)
        .collect();
    if list.is_empty() {
        None
    } else {
        Some(Arc::new(list))
    }
}

/// 日志里只打印 peer_id 前缀，减少节点日志泄露完整身份。
fn short_id(id: &str) -> &str {
    &id[..id.len().min(12)]
}

/// 单个洋葱包上限：内层载荷 64KB + 每层 94B 开销，留足余量。
/// 中继按此上限读取，避免恶意客户端用 16MB 包做内存放大。
const ONION_PACKET_MAX: usize = 128 * 1024;

/// 单节点邻居表上限，防止 PEX 无限膨胀。

/// 单次同步的重试次数（网络抖动时重试；逻辑拒绝不重试）。

fn ok() -> MailboxResponse {
    MailboxResponse {
        ok: true,
        error: None,
        messages: None,
    }
}

fn err(e: &str) -> MailboxResponse {
    MailboxResponse {
        ok: false,
        error: Some(e.to_string()),
        messages: None,
    }
}

/// 读取 peer 配置：环境变量优先，其次 data_dir/mailboxes.json。
fn load_peers(data_dir: &std::path::Path) -> Vec<String> {
    if let Ok(v) = std::env::var("PRIVCHAT_MAILBOX_PEERS") {
        let peers: Vec<String> = v
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !peers.is_empty() {
            return peers;
        }
    }
    if let Ok(bytes) = std::fs::read(data_dir.join("mailboxes.json")) {
        if let Ok(peers) = serde_json::from_slice::<Vec<String>>(&bytes) {
            return peers;
        }
    }
    Vec::new()
}

/// 当前 UTC 毫秒时间戳。
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 读取消息 TTL 配置（秒）。环境变量 `PRIVCHAT_MAILBOX_TTL_SECS` 优先，
/// 其次 `data_dir/config.json` 的 `ttl_secs`，缺省 7 天；0 = 永不过期。
fn load_ttl(data_dir: &std::path::Path) -> u64 {
    if let Ok(v) = std::env::var("PRIVCHAT_MAILBOX_TTL_SECS") {
        if let Ok(secs) = v.trim().parse::<u64>() {
            return secs;
        }
    }
    if let Ok(bytes) = std::fs::read(data_dir.join("config.json")) {
        #[derive(serde::Deserialize)]
        struct Cfg {
            ttl_secs: Option<u64>,
        }
        if let Ok(cfg) = serde_json::from_slice::<Cfg>(&bytes) {
            if let Some(secs) = cfg.ttl_secs {
                return secs;
            }
        }
    }
    7 * 24 * 3600
}

/// 首次启动兜底：若 `config.json` / `mailboxes.json` 不存在则按当前生效值
/// 落盘生成，便于用户直接编辑。已存在的文件绝不覆盖。
/// 读取节点角色：环境变量 > `config.json` 的 `role` > `both`。
fn load_role(data_dir: &std::path::Path) -> Result<String> {
    if let Ok(role) = std::env::var("PRIVCHAT_MAILBOX_ROLE") {
        return validate_role(role);
    }
    let cfg_path = data_dir.join("config.json");
    if let Ok(bytes) = std::fs::read(&cfg_path) {
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            if let Some(role) = value.get("role").and_then(|v| v.as_str()) {
                return validate_role(role.to_string());
            }
        }
    }
    Ok("both".into())
}

fn validate_role(role: String) -> Result<String> {
    if matches!(role.as_str(), "both" | "relay" | "mailbox") {
        Ok(role)
    } else {
        Err(anyhow!(
            "node role 只能是 both/relay/mailbox（环境变量 PRIVCHAT_MAILBOX_ROLE 或 config.json 的 role），当前: {role}"
        ))
    }
}

fn ensure_config_files(
    data_dir: &std::path::Path,
    ttl_secs: u64,
    peers: &[String],
    role: &str,
) -> Result<()> {
    let cfg_path = data_dir.join("config.json");
    if !cfg_path.exists() {
        std::fs::write(
            &cfg_path,
            serde_json::to_string_pretty(&serde_json::json!({
                "ttl_secs": ttl_secs,
                "role": role,
            }))?,
        )?;
        eprintln!("[mailbox] wrote {}", cfg_path.display());
    }
    let peers_path = data_dir.join("mailboxes.json");
    if !peers_path.exists() {
        std::fs::write(&peers_path, serde_json::to_string_pretty(&peers)?)?;
        eprintln!("[mailbox] wrote {}", peers_path.display());
    }
    Ok(())
}

pub async fn run() -> Result<()> {
    let data_dir = std::env::var("PRIVCHAT_MAILBOX_DATA_DIR")
        .map(PathBuf::from)
        .ok()
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|e| e.parent().map(PathBuf::from))
        })
        .unwrap_or_else(|| std::env::temp_dir().join("privchat-mailbox"));
    std::fs::create_dir_all(&data_dir)?;

    let secret_path = data_dir.join("secret.key");
    let secret_key = if let Ok(bytes) = std::fs::read(&secret_path) {
        SecretKey::try_from(bytes.as_slice())?
    } else {
        let key = SecretKey::generate();
        std::fs::write(&secret_path, key.to_bytes())?;
        key
    };

    let ttl_secs = load_ttl(&data_dir);
    let role = load_role(&data_dir)?;
    let store = MailboxStore::open(data_dir.join("mailbox.db"), ttl_secs)?;
    let peers = Arc::new(tokio::sync::Mutex::new(load_peers(&data_dir)));
    let peers_snapshot = peers.lock().await.clone();

    // 首次启动兜底：缺失的配置文件落盘，方便用户后续编辑。
    ensure_config_files(&data_dir, ttl_secs, &peers_snapshot, &role)?;

    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(secret_key.clone())
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?;

    let mailbox_handler = MailboxHandler {
        store: store.clone(),
    };

    // P2：角色分离。relay 只转发洋葱、不落库；mailbox 只存取、不参与中继；
    // both 兼容旧部署。角色来源：环境变量 > config.json > 默认 both。
    let serve_mailbox = role != "relay";
    let serve_onion = role != "mailbox";

    let mut router_builder = Router::builder(endpoint.clone());
    if serve_mailbox {
        router_builder = router_builder.accept(ALPN, mailbox_handler.clone());
    }
    let _ = serve_onion;
    router_builder = router_builder.accept(
        ONION_ALPN,
        OnionHandler {
            mailbox: mailbox_handler,
            secret: secret_key.clone(),
            endpoint: endpoint.clone(),
            allow_forward: role != "mailbox",
            allow_terminal: role != "relay",
            onion_allow: load_onion_allowlist(),
        },
    );
    let router = router_builder.spawn();

    // 到期消息清理任务：按 TTL/4 频率（夹在 1 分钟 ~ 1 小时）周期清除。
    if ttl_secs > 0 {
        let purge_store = store.clone();
        let interval_secs = (ttl_secs / 4).clamp(60, 3600);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            ticker.tick().await; // 跳过首拍
            loop {
                ticker.tick().await;
                match purge_store.purge_expired(now_ms()).await {
                    Ok(n) if n > 0 => eprintln!("[mailbox] purged {n} expired messages"),
                    Ok(_) => {}
                    Err(e) => eprintln!("[mailbox] purge failed: {e}"),
                }
            }
        });
    }

    // 等待上线（联系上 relay），确保客户端可拨号。
    // 加限时：relay 不可达（离线/被墙/内网环境）时不阻塞启动。
    let _ = tokio::time::timeout(std::time::Duration::from_secs(8), endpoint.online()).await;

    let id = endpoint.id();
    println!("PrivChat Mailbox online");
    println!("  peer_id : {id}");
    println!("  store   : {}", store.path.display());
    println!("  ttl     : {} secs (0 = never expire)", ttl_secs);
    println!("  data_dir: {}", data_dir.display());
    println!("  role    : {role} (mailbox={serve_mailbox}, onion_relay={serve_onion})");
    if peers_snapshot.is_empty() {
        println!("  peers   : (none) — 单节点模式（PEX 会自动扩充）");
    } else {
        println!("  peers   : {}", peers_snapshot.join(", "));
    }

    // 保持进程常驻。
    std::future::pending::<()>().await;
    let _ = router.shutdown().await;
    Ok(())
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

/// 测试用节点：本地回环、禁用 relay，返回可拨号端点。
pub struct TestNode {
    pub endpoint: iroh::Endpoint,
    pub router: Router,
}

impl TestNode {
    /// 拨号用的票据（无 DNS 环境直接给 peer id 也能用）。
    pub fn ticket(&self) -> String {
        use iroh_tickets::endpoint::EndpointTicket;
        use iroh_tickets::Ticket;
        EndpointTicket::new(self.endpoint.addr()).encode_string()
    }

    /// 关闭节点。
    pub async fn shutdown(self) {
        let _ = self.router.shutdown().await;
        self.endpoint.close().await;
    }
}

/// 起一个本地测试节点（回环 + 禁 relay）。
pub async fn spawn_test_node(dir: &std::path::Path, ttl_secs: u64) -> Result<TestNode> {
    std::fs::create_dir_all(dir)?;
    let store = MailboxStore::open(dir.join("mailbox.db"), ttl_secs)?;
    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(iroh::SecretKey::generate())
        .relay_mode(iroh::RelayMode::Disabled)
        .bind_addr((std::net::Ipv4Addr::LOCALHOST, 0))
        .map_err(|e| anyhow!("bind local addr: {e}"))?
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?;
    let handler = MailboxHandler { store };
    let router = Router::builder(endpoint.clone())
        .accept(ALPN, handler)
        .spawn();
    Ok(TestNode { endpoint, router })
}
