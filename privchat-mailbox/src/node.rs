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
use std::time::Instant;

use tokio::sync::Semaphore;

use anyhow::{anyhow, Result};
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::SecretKey;

use privchat_common::{hex_decode, MailboxRequest, MailboxResponse, Op, StoredMessage, ALPN};
use privchat_onion::{peel, ONION_ALPN, PACKET_MAX};

use crate::store::MailboxStore;

/// 单条请求的读取上限：队列请求最大也就一条 64KB 密文（JSON 数组约 4 倍），
/// 给到 2MB 足够，别按 16MB 收——那样 64 条并发就是 1GB 内存。
const REQUEST_MAX: usize = 2 * 1024 * 1024;

/// 同时处理的连接上限：防止对端狂开流把内存/CPU 打满。
const MAX_INFLIGHT: usize = 64;
/// 建队列速率：每秒补多少令牌、最多攒多少（防止 queue_create 刷满节点）。
const CREATE_REFILL_PER_SEC: f64 = 20.0;
const CREATE_BURST: f64 = 60.0;

/// 简单令牌桶：全局共享，够用就好。
#[derive(Debug)]
struct RateLimiter {
    state: std::sync::Mutex<(f64, Instant)>,
}

impl RateLimiter {
    fn new(burst: f64) -> Self {
        Self {
            state: std::sync::Mutex::new((burst, Instant::now())),
        }
    }

    fn allow(&self) -> bool {
        let now = Instant::now();
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        let elapsed = now.saturating_duration_since(state.1).as_secs_f64();
        state.0 = (state.0 + elapsed * CREATE_REFILL_PER_SEC).min(CREATE_BURST);
        state.1 = now;
        if state.0 >= 1.0 {
            state.0 -= 1.0;
            true
        } else {
            false
        }
    }
}

/// 连接处理循环：读一个 bi-stream，解析请求，返回响应。
#[derive(Debug, Clone)]
struct MailboxHandler {
    store: MailboxStore,
    /// 同时在处理的连接数上限。
    permits: Arc<Semaphore>,
    /// 建队列的令牌桶。
    create_limiter: Arc<RateLimiter>,
}

impl MailboxHandler {
    fn new(store: MailboxStore) -> Self {
        Self::with_limits(
            store,
            Arc::new(Semaphore::new(MAX_INFLIGHT)),
            Arc::new(RateLimiter::new(CREATE_BURST)),
        )
    }

    fn with_limits(
        store: MailboxStore,
        permits: Arc<Semaphore>,
        create_limiter: Arc<RateLimiter>,
    ) -> Self {
        Self {
            store,
            permits,
            create_limiter,
        }
    }
}

impl ProtocolHandler for MailboxHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let Ok(_permit) = self.permits.try_acquire() else {
            // 并发打满：回一句明确的「忙」，别把连接晾着。
            if let Ok((mut send, _recv)) = connection.accept_bi().await {
                let busy = MailboxResponse {
                    ok: false,
                    error: Some("node busy: too many concurrent connections".into()),
                    messages: None,
                };
                let _ = send
                    .write_all(&serde_json::to_vec(&busy).unwrap_or_default())
                    .await;
                let _ = send.finish();
            }
            return Ok(());
        };
        loop {
            let (mut send, mut recv) = match connection.accept_bi().await {
                Ok(bi) => bi,
                Err(_) => break,
            };

            let payload = match recv.read_to_end(REQUEST_MAX).await {
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

/// 洋葱终点处理器：剥掉最后一层，把最内层请求交给信箱处理。
///
/// 信箱节点**不再转发**——转发是 `privchat-relay` 的事，两个二进制各司其职。
#[derive(Debug, Clone)]
struct TerminalHandler {
    mailbox: MailboxHandler,
    secret: SecretKey,
    /// 和信箱请求共用同一个并发额度。
    permits: Arc<Semaphore>,
}

impl ProtocolHandler for TerminalHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let Ok(_permit) = self.permits.try_acquire() else {
            if let Ok((mut send, _recv)) = connection.accept_bi().await {
                let busy = MailboxResponse {
                    ok: false,
                    error: Some("node busy: too many concurrent connections".into()),
                    messages: None,
                };
                let _ = send
                    .write_all(&serde_json::to_vec(&busy).unwrap_or_default())
                    .await;
                let _ = send.finish();
            }
            return Ok(());
        };
        let remote = connection.remote_id().to_string();
        let (mut send, mut recv) = match connection.accept_bi().await {
            Ok(bi) => bi,
            Err(_) => return Ok(()),
        };
        let packet = match recv.read_to_end(PACKET_MAX).await {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("[mailbox] onion read failed: {error:#}");
                return Ok(());
            }
        };

        let response = match peel(&self.secret, &packet) {
            Ok((Some(_), _)) => MailboxResponse {
                ok: false,
                error: Some("this node is mailbox-only: use privchat-relay for relaying".into()),
                messages: None,
            },
            Ok((None, inner)) => handle_request(&self.mailbox, &inner).await,
            Err(error) => {
                eprintln!("[mailbox] onion peel failed from {remote}: {error:#}");
                MailboxResponse {
                    ok: false,
                    error: Some(format!("onion peel failed: {error:#}")),
                    messages: None,
                }
            }
        };
        let _ = send
            .write_all(&serde_json::to_vec(&response).unwrap_or_default())
            .await;
        let _ = send.finish();
        // 给对端一点时间读走最后一段响应再关连接。
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        Ok(())
    }
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
        Op::QueueRekey => handle_queue_rekey(handler, req).await,
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
    if !handler.create_limiter.allow() {
        return err("queue_create rate limited, retry later");
    }
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

/// 换 sender 公钥：owner key 签名，签的是「队列 id + 新公钥」，防止被改成别人的。
async fn handle_queue_rekey(handler: &MailboxHandler, req: MailboxRequest) -> MailboxResponse {
    let (Some(queue), Some(sender_auth), Some(sig)) = (req.queue, req.sender_auth, req.sig) else {
        return err("queue_rekey missing fields");
    };
    let Some(qid) = queue_bytes(&queue) else {
        return err("queue_rekey: bad queue id");
    };
    if sender_auth.len() != 64 {
        return err("queue_rekey: bad sender key");
    }
    let Ok(new_sender) = hex_decode(&sender_auth) else {
        return err("queue_rekey: bad hex");
    };
    let Some((_, owner_auth)) = handler.store.queue_auth(&queue).await.unwrap_or(None) else {
        return err("queue not found");
    };
    let mut msg = b"privchat/queue/rekey/v1".to_vec();
    msg.extend_from_slice(&qid);
    msg.extend_from_slice(&new_sender);
    if !verify_sig(&owner_auth, &msg, &sig) {
        return err("queue_rekey: bad signature");
    }
    match handler.store.update_queue_sender(&queue, &new_sender).await {
        Ok(1) => ok(),
        Ok(_) => err("queue not found"),
        Err(e) => err(&format!("queue_rekey failed: {e}")),
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
/// 写敏感文件：创建后立刻收到 0600（默认 umask 会留下 0644）。
fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

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
    Ok(ResolvedConfig {
        ttl_secs,
        role,
        bind,
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
    match role.as_str() {
        // both 是拆分前的旧值：现在信箱本身就是信箱终端，等价于 mailbox。
        "both" | "mailbox" => Ok("mailbox".into()),
        "relay" => Err(anyhow!(
            "中继已经拆成独立程序：请改用 privchat-relay，而不是把信箱节点的 role 设成 relay"
        )),
        other => Err(anyhow!(
            "role 只能是 mailbox（旧配置的 both 也接受），当前: {other}"
        )),
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
        max_queue_msgs: Some(cfg.max_queue_msgs),
        max_queue_bytes: Some(cfg.max_queue_bytes),
        max_queues: Some(cfg.max_queues),
    };
    write_private(&cfg_path, serde_json::to_string_pretty(&file)?.as_bytes())?;
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
        write_private(&secret_path, &key.to_bytes())?;
        key
    };

    // 配置全部来自一个 config.json（环境变量可覆盖）。
    let cfg = resolve_config(load_node_config(&data_dir))?;
    ensure_config_files(&data_dir, &cfg)?;
    let ttl_secs = cfg.ttl_secs;
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

    let mailbox_handler = MailboxHandler::new(store.clone());

    // 信箱节点只挂两个 ALPN：信箱请求 + 洋葱终点（收最内层）。
    // 转发那一半已经拆到 privchat-relay，这里不再具备中继能力。
    let router = Router::builder(endpoint.clone())
        .accept(ALPN, mailbox_handler.clone())
        .accept(
            ONION_ALPN,
            TerminalHandler {
                permits: mailbox_handler.permits.clone(),
                mailbox: mailbox_handler,
                secret: secret_key.clone(),
            },
        )
        .spawn();

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
    println!("  role    : mailbox (onion terminal only; 中继请用 privchat-relay)");
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
    let handler = MailboxHandler::new(store);
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
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn full_config_parses() {
        let dir = temp_dir("full");
        std::fs::write(
            dir.join(CONFIG_FILE),
            r#"{
                    "ttl_secs": 0,
                    "role": "both",
                    "bind": "0.0.0.0:8443",
                    "max_queue_msgs": 10,
                    "max_queue_bytes": 4096,
                    "max_queues": 99
                }"#,
        )
        .unwrap();
        let cfg = load_node_config(&dir);
        assert_eq!(cfg.ttl_secs, Some(0));
        assert_eq!(cfg.bind.as_deref(), Some("0.0.0.0:8443"));
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
    fn create_rate_limiter_bursts_then_refills() {
        let limiter = RateLimiter::new(3.0);
        assert!(limiter.allow());
        assert!(limiter.allow());
        assert!(limiter.allow());
        assert!(!limiter.allow(), "burst should be exhausted");
        std::thread::sleep(std::time::Duration::from_millis(120));
        assert!(limiter.allow(), "tokens should refill over time");
    }

    #[test]
    fn role_validation() {
        assert_eq!(validate_role("both".into()).unwrap(), "mailbox");
        assert_eq!(validate_role("mailbox".into()).unwrap(), "mailbox");
        // 中继已经拆走了，配置里写 relay 要明确拒绝并给出去处。
        assert!(validate_role("relay".into()).is_err());
        assert!(validate_role("nope".into()).is_err());
    }
}
