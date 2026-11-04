//! Layer 1 · 临时拨号身份
//!
//! 新协议里客户端**从不接受 P2P 入站**：所有收发都走 mailbox 队列。
//! 本层只做一件事：按需创建一条「临时拨号身份」（独立 SecretKey + Endpoint），
//! 用它去连 mailbox，让节点看到的 TLS 身份随连接变化，减少跨连接关联。
//!
//! 身份只在内存里：进程重启后一律换新，不落库、不恢复
//! （以前每条连接的身份都写进库、启动时全部重建端点，越用越慢）。

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use iroh::endpoint::presets;
use iroh::{Endpoint, SecretKey};
use tokio::sync::RwLock;

use crate::layers::store::Store;

/// 单个身份：独立 Endpoint（密钥用完即弃，不必留）。
struct Identity {
    endpoint: Endpoint,
}

/// L1：身份/端点管理器。
#[derive(Clone)]
pub struct Transport {
    use_relay: bool,
    identities: Arc<RwLock<HashMap<String, Arc<Identity>>>>,
}

impl Transport {
    /// 生产模式：使用 n0 默认 relay（便于 NAT 后拨号）。
    pub async fn start(_store: Arc<Store>) -> Result<Self> {
        Self::start_inner(true).await
    }

    /// 测试模式：禁用 relay、绑定回环固定端口。
    pub async fn start_no_relay(_store: Arc<Store>) -> Result<Self> {
        Self::start_inner(false).await
    }

    async fn start_inner(use_relay: bool) -> Result<Self> {
        // 身份是临时的：这里没有需要恢复的东西。
        Ok(Self {
            use_relay,
            identities: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// 指定身份的 Endpoint（拨号 mailbox 用）。
    pub async fn endpoint_for(&self, local_id: &str) -> Result<Endpoint> {
        self.identities
            .read()
            .await
            .get(local_id)
            .map(|id| id.endpoint.clone())
            .ok_or_else(|| anyhow::anyhow!("no identity endpoint for {local_id}"))
    }

    /// 新建一条临时拨号身份，返回 local_id（即 peer_id）。
    pub async fn create_identity(&self) -> Result<String> {
        let secret = SecretKey::generate();
        let local_id = secret.public().to_string();
        let id = build_identity(secret, self.use_relay).await?;
        self.identities
            .write()
            .await
            .insert(local_id.clone(), Arc::new(id));
        Ok(local_id)
    }

    /// 用完即弃：关掉端点并从表里移除（一次性拨号用，别再攒 socket）。
    pub async fn forget(&self, local_id: &str) {
        let id = self.identities.write().await.remove(local_id);
        if let Some(id) = id {
            id.endpoint.close().await;
        }
    }

    /// 关闭全部端点。
    pub async fn close(&self) {
        let ids: Vec<Arc<Identity>> = self.identities.read().await.values().cloned().collect();
        for id in ids {
            id.endpoint.close().await;
        }
    }
}

async fn build_identity(secret: SecretKey, use_relay: bool) -> Result<Identity> {
    let mut builder = Endpoint::builder(presets::N0).secret_key(secret.clone());
    if !use_relay {
        builder = builder.relay_mode(iroh::RelayMode::Disabled);
        let port = deterministic_port(&secret);
        builder = builder
            .bind_addr((std::net::Ipv4Addr::LOCALHOST, port))
            .map_err(|e| anyhow::anyhow!("bad bind addr: {e}"))?;
    }
    let endpoint = builder.bind().await?;

    if use_relay {
        // relay 不可达（离线/被墙）时不阻塞启动。
        let _ = tokio::time::timeout(std::time::Duration::from_secs(8), endpoint.online()).await;
    }
    Ok(Identity { endpoint })
}

/// 测试模式下由密钥派生固定端口，保证重启后同一身份仍可拨号。
fn deterministic_port(secret: &SecretKey) -> u16 {
    let bytes = secret.to_bytes();
    20_000 + (u16::from_be_bytes([bytes[0], bytes[1]]) % 20_000)
}
