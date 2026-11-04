//! Layer 1 · 传输与打洞层 (Transport & NAT Traversal)
//!
//! 基于 iroh (QUIC over UDP) 的端到端直连通道。
//! - 打洞: iroh `presets::N0` 内置 STUN 协商 + UDP hole punching
//! - 回退: 打洞失败自动回退到 DERP relay 中继 (iroh `RelayMode::Default`)
//!
//! 本层对上层暴露的只是「字节流信封」: `(local_id, peer_id, payload)`，
//! 不感知用户身份、队列或任何应用语义。
//!
//! ## 多身份模型（无主身份）
//!
//! iroh 的 Endpoint 身份（peer_id / TLS 证书）由 SecretKey 决定，一个
//! Endpoint 只有一个身份。本层**不设主身份**：每个联系人都由上层按需
//! 创建专属身份（独立 SecretKey + 独立 Endpoint），本端 peer_id 与
//! 联系人一一对应，跨联系人不关联。
//!
//! 邀请串 = 专属身份的 peer_id：添加联系人时本端新建一个专属身份并分享
//! 其 peer_id，对方用该身份连接；被连接方从 TLS 证书认证对端专属身份后
//! 自动登记。双方在各自联系人的对话中使用专属身份，跨联系人不关联。

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use iroh::endpoint::presets;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey};
use iroh_tickets::endpoint::EndpointTicket;
#[cfg(test)]
use iroh_tickets::Ticket;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};

use super::store::Store;

/// 本应用唯一的 ALPN 标识。
pub const ALPN: &[u8] = b"privchat/1";

/// 单个消息信封的最大字节数（L3 固定填充后仍应远小于此值）。
pub const MAX_ENVELOPE_SIZE: usize = 16 * 1024 * 1024;

/// 传输层向上层投递的原始信封。
///
/// - `local_id`：本端接收该消息时所用的专属身份（决定解密密钥）；
/// - `peer_id`：对端（发送方）的专属身份，经 TLS 认证。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomingEnvelope {
    pub local_id: String,
    pub peer_id: String,
    pub payload: Vec<u8>,
}

/// 单个专属身份：SecretKey + 独立 Endpoint + 独立路由与连接缓存。
struct Identity {
    secret: SecretKey,
    endpoint: Endpoint,
    /// 直连接收循环。生产模式（use_relay=true）为 None：不再接受 P2P 入站。
    #[allow(dead_code)]
    router: Option<Router>,
    peers: Arc<RwLock<HashMap<String, EndpointAddr>>>,
    /// 已建立的连接缓存（peer_id → QUIC 连接）。
    ///
    /// SimpleX 单向队列下，回程消息不需要重新拨号：QUIC 连接本身是
    /// 双向的，应答方直接复用对方打开的连接即可。对等连接来自被动接收。
    conns: Arc<RwLock<HashMap<String, Connection>>>,
    /// 入站信封投递通道（供拨号侧为本端发起的连接补一个读取循环）。
    tx: mpsc::UnboundedSender<IncomingEnvelope>,
}

impl Identity {
    async fn connect_peer(&self, peer_id_or_ticket: &str) -> Result<String> {
        let addr = if let Ok(ticket) = peer_id_or_ticket.parse::<EndpointTicket>() {
            ticket.endpoint_addr().clone()
        } else {
            let id: EndpointId = peer_id_or_ticket
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid ticket or peer id"))?;
            EndpointAddr::new(id)
        };
        let remote_id = addr.id.to_string();
        self.peers.write().await.insert(remote_id.clone(), addr);
        Ok(remote_id)
    }

    async fn send(&self, peer_id: &str, payload: &[u8]) -> Result<()> {
        // 先取出缓存连接（结束读锁借用），避免 if-let 的临时读锁横跨 else 分支再次加写锁造成自死锁。
        let cached = self.conns.read().await.get(peer_id).cloned();
        let conn = if let Some(conn) = cached {
            // 连接已被对端关闭（对端下线/重启）：移除缓存，走重新拨号，
            // 避免把数据写进半开的 QUIC 连接造成"发送成功但收不到"。
            if conn.close_reason().is_some() {
                self.conns.write().await.remove(peer_id);
                self.reconnect(peer_id).await?
            } else {
                conn
            }
        } else {
            self.reconnect(peer_id).await?
        };
        // 以「收到对端应答」作为送达确认：对端读完数据会关闭应答流
        // （read_to_end 立即返回）；若超时说明对方未收到，视为发送失败，
        // 并丢弃失效连接缓存，下次发送重新拨号。
        let (mut send, mut recv) = conn.open_bi().await?;
        send.write_all(payload).await?;
        send.finish()?;
        match tokio::time::timeout(std::time::Duration::from_secs(10), recv.read_to_end(1024)).await
        {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => {
                self.conns.write().await.remove(peer_id);
                Err(anyhow::anyhow!("send to {peer_id}: ack read failed: {e}"))
            }
            Err(_) => {
                self.conns.write().await.remove(peer_id);
                Err(anyhow::anyhow!("send to {peer_id}: no ack within 10s"))
            }
        }
    }

    /// 拨号并缓存连接；为拨号侧补一个读取循环。
    async fn reconnect(&self, peer_id: &str) -> Result<Connection> {
        let addr = self
            .peers
            .read()
            .await
            .get(peer_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown peer: {peer_id}"))?;
        // 拨号可能因对方离线/无直达地址而停滞，加超时防止挂死上层命令。
        let conn = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            self.endpoint.connect(addr, ALPN),
        )
        .await
        .map_err(|_| anyhow::anyhow!("connect to {peer_id} timed out"))??;
        // 拨号侧没有路由器的 accept 回调：为这条连接补一个读取循环，
        // 让回程消息（bi-stream）也能被读出并投递给上层。
        let local_id = self.endpoint.id().to_string();
        spawn_conn_reader_with_local(self.tx.clone(), conn.clone(), local_id);
        self.conns
            .write()
            .await
            .insert(peer_id.to_string(), conn.clone());
        Ok(conn)
    }
}

/// L1 传输节点：管理全部每联系人专属身份（无主身份）。
#[derive(Clone)]
pub struct Transport {
    store: Arc<Store>,
    use_relay: bool,
    /// 专属身份表：local_id → Identity。
    identities: Arc<RwLock<HashMap<String, Arc<Identity>>>>,
    /// 入站信封投递通道。
    tx: mpsc::UnboundedSender<IncomingEnvelope>,
}

impl Transport {
    /// 绑定专属身份端点并注册 ALPN 接收循环（使用 n0 默认 relay）。
    pub async fn start(
        store: Arc<Store>,
    ) -> Result<(Self, mpsc::UnboundedReceiver<IncomingEnvelope>)> {
        Self::start_inner(store, true).await
    }

    /// 以「禁用 relay、仅直连」模式启动，用于单机/内网集成测试。
    #[allow(dead_code)] // 仅由 App 的测试入口使用
    pub async fn start_no_relay(
        store: Arc<Store>,
    ) -> Result<(Self, mpsc::UnboundedReceiver<IncomingEnvelope>)> {
        Self::start_inner(store, false).await
    }

    async fn start_inner(
        store: Arc<Store>,
        use_relay: bool,
    ) -> Result<(Self, mpsc::UnboundedReceiver<IncomingEnvelope>)> {
        let (tx, rx) = mpsc::unbounded_channel();

        let transport = Self {
            store,
            use_relay,
            identities: Arc::new(RwLock::new(HashMap::new())),
            tx,
        };

        // 从数据库加载全部已持久化的专属身份（重启后恢复各联系人的身份端点）。
        // 并行构建各身份端点：每个端点等待 relay 上线（有超时），串行会把等待时间
        // 累加成 N × 超时；并行后总耗时收敛到单次最坏等待。
        let mut identities = transport.identities.write().await;
        let mut set = tokio::task::JoinSet::new();
        for (local_id, secret_bytes) in transport.store.load_identities()? {
            if let Ok(secret) = SecretKey::try_from(secret_bytes.as_slice()) {
                let tx = transport.tx.clone();
                set.spawn(async move {
                    let id = build_identity(secret, use_relay, tx).await?;
                    Ok::<_, anyhow::Error>((local_id, Arc::new(id)))
                });
            }
        }
        while let Some(res) = set.join_next().await {
            if let Ok(Ok((local_id, id))) = res {
                identities.insert(local_id, id);
            }
        }
        drop(identities);

        Ok((transport, rx))
    }

    /// 指定专属身份的长期密钥（供 crypto 层做静态 ECDH）。
    pub async fn secret_for(&self, local_id: &str) -> anyhow::Result<SecretKey> {
        let identities = self.identities.read().await;
        identities
            .get(local_id)
            .map(|id| id.secret.clone())
            .ok_or_else(|| anyhow::anyhow!("no identity for {local_id}"))
    }

    /// 指定专属身份的 Endpoint（供 mailbox 等以该身份拨号）。
    pub async fn endpoint_for(&self, local_id: &str) -> anyhow::Result<Endpoint> {
        let identities = self.identities.read().await;
        identities
            .get(local_id)
            .map(|id| id.endpoint.clone())
            .ok_or_else(|| anyhow::anyhow!("no identity endpoint for {local_id}"))
    }

    /// 供上层把（如 mailbox 解密后的）信封注入同一条投递通道。
    pub fn incoming_sender(&self) -> mpsc::UnboundedSender<IncomingEnvelope> {
        self.tx.clone()
    }

    /// 新建一个专属身份（SecretKey + 独立 Endpoint），持久化后返回其 peer_id。
    ///
    /// 每个联系人一个专属身份：调用方在分享邀请 / 建立联系人时使用。
    pub async fn create_identity(&self) -> Result<String> {
        let secret = SecretKey::generate();
        let local_id = secret.public().to_string();
        let id = build_identity(secret, self.use_relay, self.tx.clone()).await?;
        if let Err(error) = self.store.save_identity(
            &local_id,
            &id.secret.to_bytes(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_millis() as u64)
                .unwrap_or(0),
        ) {
            if let Some(router) = &id.router {
                let _ = router.shutdown().await;
            }
            id.endpoint.close().await;
            return Err(error);
        }
        self.identities
            .write()
            .await
            .insert(local_id.clone(), Arc::new(id));
        Ok(local_id)
    }

    /// 确保指定 local_id 的专属身份已就绪（从数据库恢复或新建），返回是否已存在。
    pub async fn ensure_identity(&self, local_id: &str) -> Result<bool> {
        if self.identities.read().await.contains_key(local_id) {
            return Ok(true);
        }
        let secrets = self.store.load_identities()?;
        let secret_bytes = secrets
            .get(local_id)
            .ok_or_else(|| anyhow::anyhow!("no persisted identity for {local_id}"))?;
        let secret = SecretKey::try_from(secret_bytes.as_slice())
            .map_err(|e| anyhow::anyhow!("bad stored identity: {e}"))?;
        let id = build_identity(secret, self.use_relay, self.tx.clone()).await?;
        self.identities
            .write()
            .await
            .insert(local_id.to_string(), Arc::new(id));
        Ok(true)
    }

    /// 删除一个专属身份（删除联系人时调用，释放 Endpoint 与数据库记录）。
    pub async fn drop_identity(&self, local_id: &str) {
        if let Some(identity) = self.identities.write().await.remove(local_id) {
            if let Some(router) = &identity.router {
                let _ = router.shutdown().await;
            }
            identity.endpoint.close().await;
        }
        let _ = self.store.delete_identity(local_id);
    }

    /// 通过专属身份建立对等关系并保存对方拨号地址。返回对方 peer_id。
    ///
    /// 生产路径传入的是纯 peer_id（几十字符，可放进二维码）：地址靠
    /// iroh 内置的 DNS 地址查找（Pkarr）在拨号时解析，邀请串无需携带
    /// 任何地址信息。集成测试/旧数据可能传入完整 EndpointTicket（含
    /// relay 与直连地址），也一并兼容。
    pub async fn connect_peer(&self, local_id: &str, peer_id_or_ticket: &str) -> Result<String> {
        let identities = self.identities.read().await;
        let id = identities
            .get(local_id)
            .ok_or_else(|| anyhow::anyhow!("unknown local identity: {local_id}"))?;
        let expected = self.parse_peer_id(peer_id_or_ticket)?;
        let actual = id.connect_peer(peer_id_or_ticket).await?;
        if actual != expected {
            return Err(anyhow::anyhow!(
                "identity conflict: expected {expected}, got {actual}"
            ));
        }
        Ok(actual)
    }

    /// 从邀请串（纯 peer_id 或完整票据）解析出对方 peer_id，不建立连接。
    pub fn parse_peer_id(&self, peer_id_or_ticket: &str) -> anyhow::Result<String> {
        if let Ok(ticket) = peer_id_or_ticket.parse::<EndpointTicket>() {
            Ok(ticket.endpoint_addr().id.to_string())
        } else {
            let id: EndpointId = peer_id_or_ticket
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid ticket or peer id"))?;
            Ok(id.to_string())
        }
    }

    /// 通过专属身份向对方发送一个字节信封（每条消息一个 QUIC bi-stream）。
    pub async fn send(&self, local_id: &str, peer_id: &str, payload: &[u8]) -> Result<()> {
        let identities = self.identities.read().await;
        let id = identities
            .get(local_id)
            .ok_or_else(|| anyhow::anyhow!("unknown local identity: {local_id}"))?;
        id.send(peer_id, payload).await
    }

    /// 列出全部本端专属身份，供 mailbox 轮询遍历各身份的队列。
    pub async fn local_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.identities.read().await.keys().cloned().collect();
        ids.sort();
        ids.dedup();
        ids
    }

    /// 指定专属身份的连接票据（no-relay 集成测试用）。
    #[cfg(test)]
    pub async fn ticket_for(&self, local_id: &str) -> String {
        let identities = self.identities.read().await;
        if let Some(id) = identities.get(local_id) {
            return EndpointTicket::new(id.endpoint.addr()).encode_string();
        }
        String::new()
    }

    /// 主动关闭全部专属身份路由和端点，停止所有网络活动。
    pub async fn close(&self) {
        let identities: Vec<_> = self
            .identities
            .write()
            .await
            .drain()
            .map(|(_, id)| id)
            .collect();
        for id in identities {
            if let Some(router) = &id.router {
                let _ = router.shutdown().await;
            }
            id.endpoint.close().await;
        }
    }
}

/// 构建一个专属身份端点并启动其接收循环。
async fn build_identity(
    secret: SecretKey,
    use_relay: bool,
    tx: mpsc::UnboundedSender<IncomingEnvelope>,
) -> Result<Identity> {
    // 生产模式只做「拨号方」：不注册聊天 ALPN，也不启动 P2P 接收循环。
    // 直连接收仅保留给单机集成测试（use_relay=false）。
    let mut builder = Endpoint::builder(presets::N0).secret_key(secret.clone());
    if !use_relay {
        builder = builder.alpns(vec![ALPN.to_vec()]);
        builder = builder.relay_mode(iroh::RelayMode::Disabled);
        // 单机测试：绑定由密钥派生的固定端口，保证重启后票据仍然有效。
        let port = deterministic_port(&secret);
        builder = builder
            .bind_addr((std::net::Ipv4Addr::LOCALHOST, port))
            .map_err(|e| anyhow::anyhow!("bad bind addr: {e}"))?;
    }
    let endpoint = builder.bind().await?;

    let conns: Arc<RwLock<HashMap<String, Connection>>> = Arc::new(RwLock::new(HashMap::new()));
    let peers: Arc<RwLock<HashMap<String, EndpointAddr>>> = Arc::new(RwLock::new(HashMap::new()));
    let local_id = endpoint.id().to_string();
    let router = if use_relay {
        None
    } else {
        Some(
            Router::builder(endpoint.clone())
                .accept(
                    ALPN,
                    EnvelopeHandler {
                        tx: tx.clone(),
                        conns: conns.clone(),
                        peers: peers.clone(),
                        local_id: local_id.clone(),
                    },
                )
                .spawn(),
        )
    };

    if use_relay {
        // 等待端点上线（已联系上 relay），确保地址可被远端拨号。
        // 加限时：relay 不可达（离线/被墙/模拟器无外网）时不阻塞启动，
        // 否则 `online()` 会永远等待导致解锁界面卡死。
        let _ = tokio::time::timeout(std::time::Duration::from_secs(8), endpoint.online()).await;
    }

    Ok(Identity {
        secret,
        endpoint,
        router,
        peers,
        conns,
        tx,
    })
}

/// 为一条（主动拨号建立的）连接补读循环：把收到的每个 bi-stream 投递给上层。
///
/// 被动接受的连接由 [`EnvelopeHandler::accept`] 读取，无需重复注册。
fn spawn_conn_reader_with_local(
    tx: mpsc::UnboundedSender<IncomingEnvelope>,
    conn: Connection,
    local_id: String,
) {
    tokio::spawn(async move {
        let peer_id = conn.remote_id().to_string();
        loop {
            let (mut send, mut recv) = match conn.accept_bi().await {
                Ok(bi) => bi,
                Err(_) => break,
            };
            let payload = match tokio::time::timeout(
                std::time::Duration::from_secs(30),
                recv.read_to_end(MAX_ENVELOPE_SIZE),
            )
            .await
            {
                Ok(Ok(b)) => b,
                _ => continue,
            };
            // 读完即关闭应答流：对端 `send` 的 read_to_end 立刻返回，无需等 10s 超时。
            let _ = send.finish();
            if tx
                .send(IncomingEnvelope {
                    local_id: local_id.clone(),
                    peer_id: peer_id.clone(),
                    payload,
                })
                .is_err()
            {
                break;
            }
        }
    });
}

/// 接收循环：把每个 bi-stream 读成信封投递给上层。
#[derive(Debug, Clone)]
struct EnvelopeHandler {
    tx: mpsc::UnboundedSender<IncomingEnvelope>,
    conns: Arc<RwLock<HashMap<String, Connection>>>,
    /// 该身份的 peers 地址表：入站连接登记对端地址，
    /// 使被动方之后也能主动拨号回程（重连/重发不再 "unknown peer"）。
    peers: Arc<RwLock<HashMap<String, EndpointAddr>>>,
    /// 本端接收该连接所用身份的 peer_id（该专属身份的 Endpoint 固定）。
    local_id: String,
}

impl ProtocolHandler for EnvelopeHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let peer_id = connection.remote_id().to_string();
        // 缓存入站连接：对端可通过此连接回程投递（单向队列回程）。
        self.conns
            .write()
            .await
            .insert(peer_id.clone(), connection.clone());
        // 登记对端地址（从入站连接还原）：让本端（被动方）之后也能
        // 主动拨号回去。生产路径以纯 peer_id 建立联系人，地址靠 Pkarr
        // 解析，此处按入站连接的实际路径补齐 relay/ip，重连更稳。
        {
            let mut addr = EndpointAddr::new(connection.remote_id());
            for path in connection.paths().iter() {
                match path.remote_addr() {
                    iroh::TransportAddr::Relay(url) => {
                        addr = addr.with_relay_url(url.clone());
                    }
                    iroh::TransportAddr::Ip(ip) => {
                        addr = addr.with_ip_addr(*ip);
                    }
                    iroh::TransportAddr::Custom(_) => {}
                    _ => {}
                }
            }
            self.peers.write().await.insert(peer_id.clone(), addr);
        }
        loop {
            let (mut send, mut recv) = match connection.accept_bi().await {
                Ok(bi) => bi,
                Err(_) => break,
            };
            let payload = match tokio::time::timeout(
                std::time::Duration::from_secs(30),
                recv.read_to_end(MAX_ENVELOPE_SIZE),
            )
            .await
            {
                Ok(Ok(b)) => b,
                _ => continue,
            };
            // 读完即关闭应答流：对端 `send` 的 read_to_end 立刻返回，无需等 10s 超时。
            let _ = send.finish();
            let _ = self.tx.send(IncomingEnvelope {
                local_id: self.local_id.clone(),
                peer_id: peer_id.clone(),
                payload,
            });
        }
        // 连接关闭后移除缓存，避免复用失效连接。
        self.conns.write().await.remove(&peer_id);
        Ok(())
    }
}

/// 由密钥派生出稳定的本地端口（单机测试用），范围避开特权端口。
fn deterministic_port(secret: &SecretKey) -> u16 {
    let bytes = secret.to_bytes();
    let a = u16::from(bytes[0]) << 8 | u16::from(bytes[1]);
    let b = u16::from(bytes[2]) << 8 | u16::from(bytes[3]);
    20_000 + (a ^ b) % 40_000
}
