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
use rusqlite::{params, Connection as SqlConn};
use tokio::sync::Mutex;

use privchat_mailbox::{MailboxRequest, MailboxResponse, Op, StoredMessage, ALPN, MAX_PAYLOAD};
use privchat_onion::{peel, ONION_ALPN};

/// 内存邮箱 + SQLite 持久化。
///
/// 单表 `messages`：
/// - `msg_id`      TEXT —— 发送方派生 ID，与 to_peer_id 组成主键，去重 + 排序
/// - `to_peer_id`  TEXT NOT NULL —— 接收方身份（按此分类队列）
/// - `msg`         BLOB NOT NULL —— 应用层密文
/// - `time`        INTEGER NOT NULL —— 入库时间（毫秒），TTL 到期清除依据
///
/// 另建 `idx_messages_to` 索引加速按接收方拉取。仅存密文与路由元数据，
/// 节点不接触明文。
#[derive(Clone)]
struct MailboxStore {
    conn: Arc<Mutex<SqlConn>>,
    path: PathBuf,
    /// 消息最长保留秒数；0 = 永不过期。
    ttl_secs: u64,
}

impl std::fmt::Debug for MailboxStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailboxStore")
            .field("path", &self.path)
            .finish()
    }
}

impl MailboxStore {
    /// 打开（或创建）当前版本 SQLite 库并建立表结构。
    fn open(path: PathBuf, ttl_secs: u64) -> Result<Self> {
        let conn = SqlConn::open(&path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS messages (
                 msg_id      TEXT NOT NULL,
                 to_peer_id  TEXT NOT NULL,
                 msg         BLOB NOT NULL,
                 time        INTEGER NOT NULL DEFAULT 0,
                 PRIMARY KEY (to_peer_id, msg_id)
             );
             CREATE INDEX IF NOT EXISTS idx_messages_to ON messages(to_peer_id);",
        )?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            path,
            ttl_secs,
        })
    }

    /// 存入一条消息；同一 (接收方,msg_id,payload) 幂等，不同 payload 冲突。
    async fn put(&self, msg: StoredMessage, time: u64) -> Result<bool> {
        let conn = self.conn.lock().await;
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO messages (msg_id, to_peer_id, msg, time) VALUES (?1, ?2, ?3, ?4)",
            params![msg.msg_id, msg.to_peer_id, msg.msg, time as i64],
        )?;
        if inserted == 1 {
            return Ok(true);
        }
        let same_payload: bool = conn.query_row(
            "SELECT msg = ?3 FROM messages WHERE to_peer_id = ?1 AND msg_id = ?2",
            params![msg.to_peer_id, msg.msg_id, msg.msg],
            |row| row.get(0),
        )?;
        if same_payload {
            Ok(false)
        } else {
            Err(anyhow!("msg_id conflict with different payload"))
        }
    }

    /// 拉取某接收方队列的全部密文（按 `msg_id` 升序），返回后**立即删除**
    /// （取回即删）。调用方负责向 peer 广播删除意图。
    async fn fetch(&self, recipient: &str) -> Result<Vec<StoredMessage>> {
        let conn = self.conn.lock().await;
        let mut out = Vec::new();
        {
            let mut stmt = conn.prepare(
                "SELECT msg_id, to_peer_id, msg FROM messages WHERE to_peer_id = ?1 ORDER BY msg_id",
            )?;
            let rows = stmt.query_map(params![recipient], |row| {
                Ok(StoredMessage {
                    msg_id: row.get(0)?,
                    to_peer_id: row.get(1)?,
                    msg: row.get(2)?,
                })
            })?;
            for r in rows {
                out.push(r?);
            }
        }
        if !out.is_empty() {
            let ids: Vec<String> = out.iter().map(|m| m.msg_id.clone()).collect();
            let placeholders = vec!["?"; ids.len()].join(",");
            let sql = format!(
                "DELETE FROM messages WHERE to_peer_id = ?1 AND msg_id IN ({placeholders})"
            );
            let mut stmt = conn.prepare(&sql)?;
            stmt.raw_bind_parameter(1, recipient)?;
            for (i, id) in ids.iter().enumerate() {
                stmt.raw_bind_parameter(i + 2, id)?;
            }
            stmt.raw_execute()?;
        }
        Ok(out)
    }

    /// 取出全部待收密文（PEX 学习到新节点时的一次性补推，带上限）。
    async fn list_all(&self, limit: usize) -> Result<Vec<StoredMessage>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT msg_id, to_peer_id, msg FROM messages ORDER BY time DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(StoredMessage {
                msg_id: row.get(0)?,
                to_peer_id: row.get(1)?,
                msg: row.get(2)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// 删除已超过 TTL 的消息，返回删除行数。
    async fn purge_expired(&self, now_ms: u64) -> Result<usize> {
        if self.ttl_secs == 0 {
            return Ok(0);
        }
        let cutoff = now_ms.saturating_sub(self.ttl_secs * 1000);
        let conn = self.conn.lock().await;
        let deleted = conn.execute(
            "DELETE FROM messages WHERE time < ?1",
            params![cutoff as i64],
        )?;
        Ok(deleted)
    }

    /// 删除对应 msg_id（仅限该接收方的队列），返回删除行数。由网格 `sync_ack`
    /// 触发（fetch 取回即删 / 节点间删除同步）；返回 0 表示本节点本就没有
    /// 这些消息（幂等，无需再转发，切断环路）。
    async fn ack(&self, recipient: &str, ids: &[String]) -> Result<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let conn = self.conn.lock().await;
        let placeholders = vec!["?"; ids.len()].join(",");
        let sql =
            format!("DELETE FROM messages WHERE to_peer_id = ?1 AND msg_id IN ({placeholders})");
        let mut stmt = conn.prepare(&sql)?;
        stmt.raw_bind_parameter(1, recipient)?;
        for (i, id) in ids.iter().enumerate() {
            stmt.raw_bind_parameter(i + 2, id)?;
        }
        let deleted = stmt.raw_execute()?;
        Ok(deleted)
    }
}

/// 连接处理循环：读一个 bi-stream，解析请求，返回响应。
#[derive(Debug, Clone)]
struct MailboxHandler {
    store: MailboxStore,
    endpoint: iroh::Endpoint,
    /// 其他 mailbox 节点的 peer_id（全连通/链式/环状均可）。
    peers: Arc<tokio::sync::Mutex<Vec<String>>>,
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
                        peers: None,
                    };
                    let _ = send.write_all(&serde_json::to_vec(&response).unwrap_or_default()).await;
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
                            peers: None,
                        };
                        let _ = send.write_all(&serde_json::to_vec(&response).unwrap_or_default()).await;
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
                        peers: None,
                    },
                    Ok(resp) => MailboxResponse {
                        ok: false,
                        error: Some(format!(
                            "downstream {next} rejected: {}",
                            resp.error.unwrap_or_default()
                        )),
                        messages: None,
                        peers: None,
                    },
                    Err(error) => MailboxResponse {
                        ok: false,
                        error: Some(format!("relay to {next} failed: {error:#}")),
                        messages: None,
                        peers: None,
                    },
                };
                let wrote = send.write_all(&serde_json::to_vec(&response).unwrap_or_default()).await;
                eprintln!("[onion] response write ok={}", wrote.is_ok());
                let _ = send.finish();
            }
            Ok((None, inner)) => {
                if !self.allow_terminal {
                    let response = MailboxResponse {
                        ok: false,
                        error: Some("this node is relay-only: refusing terminal delivery".into()),
                        messages: None,
                        peers: None,
                    };
                    let _ = send.write_all(&serde_json::to_vec(&response).unwrap_or_default()).await;
                    let _ = send.finish();
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    return Ok(());
                }
                // 终点：只允许匿名投递（put），fetch 需要真实身份队列认证。
                let response = handle_request(&self.mailbox, &remote, &inner).await;
                let _ = send.write_all(&serde_json::to_vec(&response).unwrap_or_default()).await;
                let _ = send.finish();
            }
            Err(error) => {
                eprintln!("[onion] peel failed from {remote}: {error:#}");
                let response = MailboxResponse {
                    ok: false,
                    error: Some(format!("onion peel failed: {error:#}")),
                    messages: None,
                    peers: None,
                };
                let _ = send.write_all(&serde_json::to_vec(&response).unwrap_or_default()).await;
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
    let bytes = tokio::time::timeout(
        std::time::Duration::from_secs(90),
        recv.read_to_end(4096),
    )
    .await
    .map_err(|_| anyhow!("waiting {next} response timed out"))??;
    let response: MailboxResponse = serde_json::from_slice(&bytes)
        .map_err(|e| anyhow!("bad response from {next}: {e}"))?;
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
    if matches!(req.op, Op::Sync | Op::SyncAck)
        && !handler.peers.lock().await.iter().any(|peer| peer == remote_id)
    {
        return err("mailbox sync forbidden: sender is not a configured peer");
    }

    match req.op {
        Op::Ping => ok(),
        Op::Peers => {
            let known: Vec<String> = handler.peers.lock().await.clone();
            MailboxResponse {
                ok: true,
                error: None,
                messages: None,
                peers: Some(known),
            }
        }
        Op::Put => match StoredMessage::from_request(&req) {
            Ok(msg) => {
                if msg.msg.len() > MAX_PAYLOAD {
                    return err("payload too large");
                }
                // 防垃圾：校验工作量证明，不满足直接拒绝（不存储、不广播）。
                let nonce = req.nonce.unwrap_or(0);
                if !privchat_mailbox::verify_pow(&msg.to_peer_id, &msg.msg, nonce) {
                    return err("pow verification failed");
                }
                match handler.store.put(msg.clone(), now_ms()).await {
                    Ok(true) => {
                        // 本地持久化后立即响应；网格同步转后台，避免慢 peer
                        // 让客户端误判 PUT 超时并回滚发送棘轮。
                        spawn_broadcast(
                            handler.endpoint.clone(),
                            handler.peers.lock().await.clone(),
                            MailboxRequest {
                                op: Op::Sync,
                                msg: Some(msg),
                                to: None,
                                for_peer: None,
                                id: None,
                                ids: None,
                                payload: None,
                                nonce: None,
                            },
                        );
                        ok()
                    }
                    Ok(false) => ok(), // msg_id 已存在，幂等
                    Err(e) => err(&format!("store failed: {e}")),
                }
            }
            Err(e) => err(&e.to_string()),
        },
        Op::Fetch => {
            let recipient = match req.for_peer {
                Some(r) => r,
                None => return err("fetch missing for"),
            };
            // 队列归属认证：只能拉取自己身份的队列，防他人「取回即删」式 DoS。
            if recipient != remote_id {
                return err("fetch forbidden: queue belongs to another identity");
            }
            match handler.store.fetch(&recipient).await {
                Ok(messages) => {
                    // 取回即删：本节点已删除，向 peer 广播删除意图，
                    // 网格同步清掉其他节点的副本。
                    if !messages.is_empty() {
                        let ids: Vec<String> = messages.iter().map(|m| m.msg_id.clone()).collect();
                        spawn_broadcast(
                            handler.endpoint.clone(),
                            handler.peers.lock().await.clone(),
                            MailboxRequest {
                                op: Op::SyncAck,
                                to: Some(recipient),
                                ids: Some(ids),
                                for_peer: None,
                                id: None,
                                payload: None,
                                msg: None,
                                nonce: None,
                            },
                        );
                    }
                    MailboxResponse {
                        ok: true,
                        error: None,
                        messages: Some(messages),
                        peers: None,
                    }
                }
                Err(e) => err(&format!("fetch failed: {e}")),
            }
        }
        Op::Sync => {
            // 来自其他 mailbox 的同步广播：仅在**真正新增**时继续转发，
            // msg_id 主键幂等保证每条消息每节点至多处理一次 → 多跳链路可通、
            // 环路被截断（新增过一次后必为 0，不再广播）。
            match req.msg {
                Some(msg) => match handler.store.put(msg.clone(), now_ms()).await {
                    Ok(true) => {
                        spawn_broadcast(
                            handler.endpoint.clone(),
                            handler.peers.lock().await.clone(),
                            MailboxRequest {
                                op: Op::Sync,
                                msg: Some(msg),
                                to: None,
                                for_peer: None,
                                id: None,
                                ids: None,
                                payload: None,
                                nonce: None,
                            },
                        );
                        ok()
                    }
                    Ok(false) => ok(), // 已存在，幂等，不再转发
                    Err(e) => err(&format!("store failed: {e}")),
                },
                None => err("sync missing msg"),
            }
        }
        Op::SyncAck => {
            let recipient = match req.to {
                Some(t) => t,
                None => return err("sync_ack missing to"),
            };
            let ids = req.ids.unwrap_or_default();
            match handler.store.ack(&recipient, &ids).await {
                Ok(deleted) => {
                    // 本节点确实删除了消息才继续转发；否则说明已删除过，
                    // 不再广播，切断环路。
                    if deleted > 0 {
                        spawn_broadcast(
                            handler.endpoint.clone(),
                            handler.peers.lock().await.clone(),
                            MailboxRequest {
                                op: Op::SyncAck,
                                to: Some(recipient),
                                ids: Some(ids),
                                for_peer: None,
                                id: None,
                                payload: None,
                                msg: None,
                                nonce: None,
                            },
                        );
                    }
                    ok()
                }
                Err(e) => err(&format!("ack failed: {e}")),
            }
        }
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
const MAX_PEERS: usize = 64;

/// 邻居交换（PEX）：定期向已知 mailbox 询问它们认识谁，自动扩充列表并落盘。
///
/// - 只向**当前已知**的节点询问，不接受陌生人主动推送 → 信任沿已有边扩散
/// - 只接受 64 位十六进制、非自身、未重复的 id
/// - 有新节点才重写 `mailboxes.json`
fn spawn_peer_exchange(
    endpoint: iroh::Endpoint,
    peers: Arc<tokio::sync::Mutex<Vec<String>>>,
    data_dir: PathBuf,
    store: MailboxStore,
) {
    let interval_secs: u64 = std::env::var("PRIVCHAT_MAILBOX_PEX_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v >= 5)
        .unwrap_or(60);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        loop {
            ticker.tick().await;
            let current = peers.lock().await.clone();
            if current.is_empty() {
                continue;
            }
            let self_id = endpoint.id().to_string();
            let mut added: Vec<String> = Vec::new();
            for peer in current {
                let request = MailboxRequest::peers();
                let Ok(response) = privchat_mailbox::send_request(&endpoint, &peer, &request).await
                else {
                    continue;
                };
                if !response.ok {
                    continue;
                }
                let Some(known) = response.peers else {
                    continue;
                };
                let mut list = peers.lock().await;
                for id in known {
                    if id == self_id {
                        continue;
                    }
                    if id.len() != 64 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
                        continue;
                    }
                    if list.iter().any(|existing| existing == &id) {
                        continue;
                    }
                    if list.len() >= MAX_PEERS {
                        break;
                    }
                    list.push(id.clone());
                    added.push(id);
                }
            }
            if !added.is_empty() {
                let snapshot = peers.lock().await.clone();
                if let Ok(json) = serde_json::to_string_pretty(&snapshot) {
                    if let Err(error) = std::fs::write(data_dir.join("mailboxes.json"), json) {
                        eprintln!("[mailbox] failed to persist peers: {error}");
                    }
                }
                eprintln!("[mailbox] PEX learned {} peer(s): {added:?}", added.len());
                // 给新邻居补推本节点已有的消息，避免它空着（限量，后台执行）。
                let messages = store.list_all(200).await.unwrap_or_default();
                for peer in &added {
                    for msg in &messages {
                        let request = MailboxRequest {
                            op: Op::Sync,
                            to: None,
                            for_peer: None,
                            id: None,
                            ids: None,
                            payload: None,
                            nonce: None,
                            msg: Some(msg.clone()),
                        };
                        let _ = sync_with_retry(&endpoint, peer, &request).await;
                    }
                }
            }
        }
    });
}

/// 单次同步的重试次数（网络抖动时重试；逻辑拒绝不重试）。
const SYNC_ATTEMPTS: usize = 3;

fn spawn_broadcast(endpoint: iroh::Endpoint, peers: Vec<String>, req: MailboxRequest) {
    tokio::spawn(async move {
        let mut requests = tokio::task::JoinSet::new();
        let req = Arc::new(req);
        for peer in peers {
            let endpoint = endpoint.clone();
            let req = Arc::clone(&req);
            requests.spawn(async move {
                let result = sync_with_retry(&endpoint, &peer, req.as_ref()).await;
                (peer, result)
            });
        }
        while let Some(result) = requests.join_next().await {
            match result {
                Ok((peer, Err(e))) => eprintln!("[mailbox] sync to {peer} failed: {e:#}"),
                Err(e) => eprintln!("[mailbox] sync task failed: {e}"),
                Ok((_, Ok(()))) => {}
            }
        }
    });
}

/// 带指数退避的同步：网络错误重试，逻辑拒绝（resp.ok=false）直接放弃。
async fn sync_with_retry(
    endpoint: &iroh::Endpoint,
    peer: &str,
    req: &MailboxRequest,
) -> Result<()> {
    let mut last_error = None;
    for attempt in 1..=SYNC_ATTEMPTS {
        match privchat_mailbox::send_request(endpoint, peer, req).await {
            Ok(response) if response.ok => return Ok(()),
            Ok(response) => {
                return Err(anyhow!(
                    "sync rejected by {peer}: {}",
                    response.error.unwrap_or_default()
                ))
            }
            Err(error) => {
                last_error = Some(error);
                if attempt < SYNC_ATTEMPTS {
                    tokio::time::sleep(std::time::Duration::from_millis(500 * attempt as u64)).await;
                }
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow!("sync failed")))
}

fn ok() -> MailboxResponse {
    MailboxResponse {
        ok: true,
        error: None,
        messages: None,
        peers: None,
    }
}

fn err(e: &str) -> MailboxResponse {
    MailboxResponse {
        ok: false,
        error: Some(e.to_string()),
        messages: None,
        peers: None,
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

#[tokio::main]
async fn main() -> Result<()> {
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
        endpoint: endpoint.clone(),
        peers: peers.clone(),
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

    // 邻居自动扩充：周期向已知节点询问它们的邻居列表。
    spawn_peer_exchange(
        endpoint.clone(),
        peers.clone(),
        data_dir.clone(),
        store.clone(),
    );

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
mod tests;
