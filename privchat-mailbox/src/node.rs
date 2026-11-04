//! PrivChat Mailbox —— 离线消息缓存节点
//!
//! 纯存储节点：不参与任何会话加密。客户端先做应用层加密（双棘轮，见
//! client 的 `crypto::Ratchet`），再把密文 `payload` 交给本节点暂存。
//! 本节点只按「队列 id」存取、按消息 ID 排序与删除，永不接触明文。
//!
//! ## 取回即删 + TTL
//! `QueueGet` 按 `msg_id` 升序返回该队列的全部密文，返回后立即从本节点
//! 删除。msg_id 由发送方从加密头的 `(gen, n)`（逻辑发送序）派生，故按
//! msg_id 排序即等于棘轮消息顺序；不含时间戳，不泄露收发时间。
//! 消息最长保留时间（TTL）可配置，到期由后台任务清除：
//! - 环境变量 `PRIVCHAT_MAILBOX_TTL_SECS`（秒，0 = 永不过期），或
//! - `data_dir/config.json` 的 `{"ttl_secs": <秒>}`；缺省 7 天。
//!
//! ## 节点之间不通信
//! 每条队列只属于一台 mailbox：客户端直接连这台节点读写，不存在副本，
//! 因此没有消息同步 / 补推 / 反熵，也没有邻居表与 PEX。跨节点流量只剩
//! 可选的洋葱中继（`ONION_ALPN` 逐层转发）。
//!
//! 队列轮换时由客户端新建一条队列（可以落在另一台节点），旧队列排空后
//! 再删除，数据不搬迁。

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::SecretKey;

use privchat_common::{
    hex_decode, MailboxRequest, MailboxResponse, Op, StoredMessage, ALPN, MAX_PAYLOAD,
};
use privchat_onion::{peel, ONION_ALPN};

use crate::store::MailboxStore;

/// 连接处理循环：读一个 bi-stream，解析请求，返回响应。
#[derive(Debug, Clone)]
struct MailboxHandler {
    store: MailboxStore,
}

impl ProtocolHandler for MailboxHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
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

            let response = handle_request(self, &payload).await;
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
                match forward_onion(&endpoint, &next, inner).await {
                    // 原样回传：中继不解析内容，也就不会把 messages 弄丢。
                    Ok(raw) => {
                        let wrote = send.write_all(&raw).await;
                        eprintln!("[onion] response relayed ok={}", wrote.is_ok());
                    }
                    Err(error) => {
                        eprintln!("[onion] forward to {next} failed: {error:#}");
                        let response = MailboxResponse {
                            ok: false,
                            error: Some(format!("relay to {next} failed: {error:#}")),
                            messages: None,
                        };
                        let _ = send
                            .write_all(&serde_json::to_vec(&response).unwrap_or_default())
                            .await;
                    }
                }
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
                // 终点：把最内层请求交给 mailbox 处理（队列鉴权在请求体内）。
                let response = handle_request(&self.mailbox, &inner).await;
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
async fn forward_onion(endpoint: &iroh::Endpoint, next: &str, inner: Vec<u8>) -> Result<Vec<u8>> {
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
    // 响应可能是一整批密文（queue_get），给足上限；中继只看长度不看内容。
    let bytes = tokio::time::timeout(
        std::time::Duration::from_secs(90),
        recv.read_to_end(ONION_RESPONSE_MAX),
    )
    .await
    .map_err(|_| anyhow!("waiting {next} response timed out"))??;
    Ok(bytes)
}

async fn handle_request(handler: &MailboxHandler, payload: &[u8]) -> MailboxResponse {
    let req: MailboxRequest = match serde_json::from_slice(payload) {
        Ok(r) => r,
        Err(e) => return err(&format!("bad request: {e}")),
    };
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

fn queue_bytes(q: &str) -> Option<[u8; 16]> {
    if q.len() != 32 {
        return None;
    }
    hex_decode(q).ok()?.as_slice().try_into().ok()
}

fn verify_sig(pubkey: &[u8], msg: &[u8], sig_hex: &str) -> bool {
    let Ok(pk) = <[u8; 32]>::try_from(pubkey) else {
        return false;
    };
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    let Ok(sig_bytes) = hex_decode(sig_hex) else {
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
    let (Ok(sender), Ok(owner)) = (hex_decode(&sender_auth), hex_decode(&owner_auth)) else {
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

/// 日志里只打印 peer_id 前缀，减少节点日志泄露完整身份。
fn short_id(id: &str) -> &str {
    &id[..id.len().min(12)]
}

/// 单个洋葱包上限：内层载荷 64KB + 每层 94B 开销，留足余量。
/// 中继按此上限读取，避免恶意客户端用 16MB 包做内存放大。
const ONION_PACKET_MAX: usize = 128 * 1024;
const ONION_RESPONSE_MAX: usize = 32 * 1024 * 1024;

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

/// 当前 UTC 毫秒时间戳。
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 节点配置：`data_dir/config.json` 一个文件装下所有可调项。
///
/// 优先级：环境变量 > config.json > 默认值。
/// 环境变量留着是因为 systemd / docker 里覆盖最方便，日常改配置只动 json。
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct NodeConfig {
    /// 密文保留秒数，0 = 永不过期。
    #[serde(default)]
    ttl_secs: Option<u64>,
    /// both / mailbox / relay。
    #[serde(default)]
    role: Option<String>,
    /// 固定监听地址，例如 "0.0.0.0:8443"；不写则随机端口。
    #[serde(default)]
    bind: Option<String>,
    /// 洋葱转发白名单（逗号分隔的 peer_id 列表）；空 = 不限制。
    #[serde(default)]
    onion_peers: Option<Vec<String>>,
    /// 单队列条数上限。
    #[serde(default)]
    max_queue_msgs: Option<usize>,
    /// 单队列字节上限。
    #[serde(default)]
    max_queue_bytes: Option<usize>,
    /// 节点上队列总数上限。
    #[serde(default)]
    max_queues: Option<usize>,
}

const CONFIG_FILE: &str = "config.json";

/// 生效配置：环境变量已经叠到文件配置上，后面直接用。
struct ResolvedConfig {
    ttl_secs: u64,
    role: String,
    bind: Option<String>,
    onion_peers: Vec<String>,
    max_queue_msgs: usize,
    max_queue_bytes: usize,
    max_queues: usize,
}

/// 读 config.json；不存在或写坏了就当成空配置（全部走默认）。
fn load_node_config(data_dir: &std::path::Path) -> NodeConfig {
    let path = data_dir.join(CONFIG_FILE);
    let Ok(bytes) = std::fs::read(&path) else {
        return NodeConfig::default();
    };
    match serde_json::from_slice::<NodeConfig>(&bytes) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("[mailbox] config.json 解析失败，按默认值启动: {e}");
            NodeConfig::default()
        }
    }
}

fn env_string(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn env_usize(key: &str) -> Option<usize> {
    env_string(key).and_then(|v| v.parse().ok())
}

fn env_u64(key: &str) -> Option<u64> {
    env_string(key).and_then(|v| v.parse().ok())
}

fn is_peer_id(id: &str) -> bool {
    id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit())
}

fn resolve_config(file: NodeConfig) -> Result<ResolvedConfig> {
    let ttl_secs = env_u64("PRIVCHAT_MAILBOX_TTL_SECS")
        .or(file.ttl_secs)
        .unwrap_or(7 * 24 * 3600);
    let role = validate_role(
        env_string("PRIVCHAT_MAILBOX_ROLE")
            .or(file.role)
            .unwrap_or_else(|| "both".into()),
    )?;
    let bind = env_string("PRIVCHAT_MAILBOX_BIND").or(file.bind);
    let onion_peers = match env_string("PRIVCHAT_MAILBOX_ONION_PEERS") {
        Some(raw) => raw
            .split(',')
            .map(str::trim)
            .filter(|p| is_peer_id(p))
            .map(str::to_string)
            .collect(),
        None => file
            .onion_peers
            .unwrap_or_default()
            .into_iter()
            .filter(|p| is_peer_id(p))
            .collect(),
    };
    Ok(ResolvedConfig {
        ttl_secs,
        role,
        bind,
        onion_peers,
        max_queue_msgs: env_usize("PRIVCHAT_MAILBOX_MAX_QUEUE_MSGS")
            .or(file.max_queue_msgs)
            .unwrap_or(1000),
        max_queue_bytes: env_usize("PRIVCHAT_MAILBOX_MAX_QUEUE_BYTES")
            .or(file.max_queue_bytes)
            .unwrap_or(64 * 1024 * 1024),
        max_queues: env_usize("PRIVCHAT_MAILBOX_MAX_QUEUES")
            .or(file.max_queues)
            .unwrap_or(50_000),
    })
}

fn validate_role(role: String) -> Result<String> {
    if matches!(role.as_str(), "both" | "relay" | "mailbox") {
        Ok(role)
    } else {
        Err(anyhow!(
            "node role 只能是 both/relay/mailbox（config.json 的 role 或环境变量 PRIVCHAT_MAILBOX_ROLE），当前: {role}"
        ))
    }
}

/// 首次启动兜底：把当前生效配置写进 config.json，方便用户照着改。
/// 已存在的文件绝不覆盖。
fn ensure_config_files(data_dir: &std::path::Path, cfg: &ResolvedConfig) -> Result<()> {
    let cfg_path = data_dir.join(CONFIG_FILE);
    if cfg_path.exists() {
        return Ok(());
    }
    let file = NodeConfig {
        ttl_secs: Some(cfg.ttl_secs),
        role: Some(cfg.role.clone()),
        bind: cfg.bind.clone(),
        onion_peers: if cfg.onion_peers.is_empty() {
            None
        } else {
            Some(cfg.onion_peers.clone())
        },
        max_queue_msgs: Some(cfg.max_queue_msgs),
        max_queue_bytes: Some(cfg.max_queue_bytes),
        max_queues: Some(cfg.max_queues),
    };
    std::fs::write(&cfg_path, serde_json::to_string_pretty(&file)?)?;
    eprintln!("[mailbox] wrote {}", cfg_path.display());
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

    // 配置全部来自一个 config.json（环境变量可覆盖）。
    let cfg = resolve_config(load_node_config(&data_dir))?;
    ensure_config_files(&data_dir, &cfg)?;
    let ttl_secs = cfg.ttl_secs;
    let role = cfg.role.clone();
    let store = MailboxStore::open_with_limits(
        data_dir.join("mailbox.db"),
        cfg.ttl_secs,
        cfg.max_queue_msgs,
        cfg.max_queue_bytes,
        cfg.max_queues,
    )?;

    let mut endpoint_builder = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(secret_key.clone())
        .alpns(vec![ALPN.to_vec()]);
    // 公网部署常用：固定监听地址/端口，客户端可以直接拨。
    // 不设则随机端口，只能靠 relay + 发现服务找到。
    if let Some(bind) = &cfg.bind {
        let addr: std::net::SocketAddr = bind
            .parse()
            .map_err(|e| anyhow!("config.json 的 bind 不是合法地址 {bind}: {e}"))?;
        endpoint_builder = endpoint_builder
            .bind_addr(addr)
            .map_err(|e| anyhow!("bind_addr {addr} 失败: {e}"))?;
    }
    let endpoint = endpoint_builder.bind().await?;

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
            onion_allow: if cfg.onion_peers.is_empty() {
                None
            } else {
                Some(Arc::new(cfg.onion_peers.clone()))
            },
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
    if let Some(bind) = &cfg.bind {
        println!("  bind    : {bind}");
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

#[cfg(test)]
mod config_tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("privchat-node-cfg-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn old_config_without_new_fields_still_loads() {
        let dir = temp_dir("old");
        std::fs::write(
            dir.join(CONFIG_FILE),
            r#"{"ttl_secs": 60, "role": "relay"}"#,
        )
        .unwrap();
        let cfg = load_node_config(&dir);
        assert_eq!(cfg.ttl_secs, Some(60));
        assert_eq!(cfg.role.as_deref(), Some("relay"));
        assert!(cfg.bind.is_none());
        assert!(cfg.onion_peers.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn full_config_parses() {
        let dir = temp_dir("full");
        let peer = "ab".repeat(32);
        std::fs::write(
            dir.join(CONFIG_FILE),
            format!(
                r#"{{
                    "ttl_secs": 0,
                    "role": "both",
                    "bind": "0.0.0.0:8443",
                    "onion_peers": ["{peer}"],
                    "max_queue_msgs": 10,
                    "max_queue_bytes": 4096,
                    "max_queues": 99
                }}"#
            ),
        )
        .unwrap();
        let cfg = load_node_config(&dir);
        assert_eq!(cfg.ttl_secs, Some(0));
        assert_eq!(cfg.bind.as_deref(), Some("0.0.0.0:8443"));
        assert_eq!(cfg.onion_peers.as_ref().unwrap()[0], peer);
        assert_eq!(cfg.max_queue_msgs, Some(10));
        assert_eq!(cfg.max_queue_bytes, Some(4096));
        assert_eq!(cfg.max_queues, Some(99));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn broken_config_falls_back_to_defaults() {
        let dir = temp_dir("broken");
        std::fs::write(dir.join(CONFIG_FILE), "{not json").unwrap();
        let cfg = load_node_config(&dir);
        assert!(cfg.role.is_none());
        assert!(cfg.ttl_secs.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn role_validation() {
        assert!(validate_role("both".into()).is_ok());
        assert!(validate_role("relay".into()).is_ok());
        assert!(validate_role("mailbox".into()).is_ok());
        assert!(validate_role("nope".into()).is_err());
    }
}
