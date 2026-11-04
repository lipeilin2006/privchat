//! 连接管理：把 `connection::Link` 与 mailbox 队列原语接起来。
//!
//! 队列权限靠签名（与 TLS 身份无关），所以网络层被抽成 [`QueueApi`]：
//! 生产实现走 iroh + mailbox，测试实现走内存。这样连接流程可以离线跑通。

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;
use iroh::Endpoint;
use tokio::sync::Mutex;

use crate::layers::app::{OnionConfig, OnionMode, OnionRelay};
use crate::layers::connection::{
    self, DrainingQueue, Invite, Link, LinkState, OutQueue, PartialFile, QueueKeys,
};
use crate::layers::crypto::connection::Connection as E2e;
use crate::layers::mailbox::MailboxClient;
use crate::layers::store::{ConnRow, Store};
use crate::layers::transport::Transport;
use privchat_common::{send_request, MailboxRequest, MailboxResponse};

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// 队列操作的抽象：生产走 mailbox，测试走内存。
pub trait QueueApi: Send + Sync {
    fn create<'a>(
        &'a self,
        conn_id: &'a str,
        mailbox: &'a str,
        queue: &'a str,
        sender_pub: &'a str,
        owner_pub: &'a str,
        ttl_ms: Option<u64>,
    ) -> BoxFut<'a, ()>;

    fn send<'a>(
        &'a self,
        conn_id: &'a str,
        mailbox: &'a str,
        queue: &'a str,
        payload: Vec<u8>,
        sig: &'a str,
    ) -> BoxFut<'a, ()>;

    fn get<'a>(
        &'a self,
        conn_id: &'a str,
        mailbox: &'a str,
        queue: &'a str,
        sig: &'a str,
    ) -> BoxFut<'a, Vec<Vec<u8>>>;

    fn delete<'a>(
        &'a self,
        conn_id: &'a str,
        mailbox: &'a str,
        queue: &'a str,
        sig: &'a str,
    ) -> BoxFut<'a, ()>;
}

/// 生产实现：每个连接一条临时拨号端点（队列权限靠签名，不靠 TLS 身份）。
pub struct IrohQueues {
    transport: Transport,
    endpoints: Mutex<HashMap<String, Endpoint>>,
    /// 洋葱配置：开了就把请求逐层包好再送出去。
    onion: Arc<Mutex<OnionConfig>>,
    /// 中继的实测延迟（动态模式下按权重随机挑路径用）。
    relay_latency: Arc<Mutex<HashMap<String, u64>>>,
}

impl IrohQueues {
    pub fn new(
        transport: Transport,
        onion: Arc<Mutex<OnionConfig>>,
        relay_latency: Arc<Mutex<HashMap<String, u64>>>,
    ) -> Self {
        Self {
            transport,
            endpoints: Mutex::new(HashMap::new()),
            onion,
            relay_latency,
        }
    }

    async fn endpoint(&self, conn_id: &str) -> Result<Endpoint> {
        let mut map = self.endpoints.lock().await;
        if let Some(ep) = map.get(conn_id) {
            return Ok(ep.clone());
        }
        let local_id = self.transport.create_identity().await?;
        let ep = self.transport.endpoint_for(&local_id).await?;
        map.insert(conn_id.to_string(), ep.clone());
        Ok(ep)
    }

    /// 洋葱路径：中继 + 终点 mailbox。没开或没配中继就返回 None。
    ///
    /// 静态：按配置顺序整条走。
    /// 动态：每发一次从池子里按权重随机挑 `hops` 跳——优先级越高、延迟越低
    /// 越容易被选中，两个因素的权重大小都能调。
    async fn onion_path(&self, mailbox: &str) -> Option<Vec<String>> {
        let config = self.onion.lock().await.clone();
        if !config.enabled {
            return None;
        }
        let pool: Vec<OnionRelay> = config
            .relays
            .iter()
            .filter(|relay| is_peer_id(&relay.peer_id) && relay.peer_id != mailbox)
            .cloned()
            .collect();
        if pool.is_empty() {
            return None;
        }
        let relays: Vec<String> = match config.mode {
            OnionMode::Static => pool.iter().map(|relay| relay.peer_id.clone()).collect(),
            OnionMode::Dynamic => {
                let latencies = self.relay_latency.lock().await.clone();
                sample_relays(&pool, config.hops as usize, config.weight, &latencies)
            }
        };
        if relays.is_empty() {
            return None;
        }
        let mut path = relays;
        path.push(mailbox.to_string());
        Some(path)
    }

    async fn call(
        &self,
        conn_id: &str,
        mailbox: &str,
        req: &MailboxRequest,
    ) -> Result<MailboxResponse> {
        let endpoint = self.endpoint(conn_id).await?;
        match self.onion_path(mailbox).await {
            Some(path) => {
                let body = serde_json::to_vec(req)?;
                let packet = privchat_onion::wrap(&path, &body)?;
                MailboxClient::request_via_onion(&endpoint, &path[0], packet).await
            }
            None => send_request(&endpoint, mailbox, req).await,
        }
    }

    fn check(resp: MailboxResponse, what: &str) -> Result<MailboxResponse> {
        if resp.ok {
            Ok(resp)
        } else {
            Err(anyhow!("{what} failed: {}", resp.error.unwrap_or_default()))
        }
    }
}

impl QueueApi for IrohQueues {
    fn create<'a>(
        &'a self,
        conn_id: &'a str,
        mailbox: &'a str,
        queue: &'a str,
        sender_pub: &'a str,
        owner_pub: &'a str,
        ttl_ms: Option<u64>,
    ) -> BoxFut<'a, ()> {
        Box::pin(async move {
            let req = match ttl_ms {
                Some(ttl) if ttl > 0 => {
                    MailboxRequest::queue_create_invite(queue, sender_pub, owner_pub, ttl)
                }
                _ => MailboxRequest::queue_create(queue, sender_pub, owner_pub),
            };
            let resp = self.call(conn_id, mailbox, &req).await?;
            Self::check(resp, "queue_create").map(|_| ())
        })
    }

    fn send<'a>(
        &'a self,
        conn_id: &'a str,
        mailbox: &'a str,
        queue: &'a str,
        payload: Vec<u8>,
        sig: &'a str,
    ) -> BoxFut<'a, ()> {
        Box::pin(async move {
            let req = MailboxRequest::queue_send(queue, payload, sig);
            let resp = self.call(conn_id, mailbox, &req).await?;
            Self::check(resp, "queue_send").map(|_| ())
        })
    }

    fn get<'a>(
        &'a self,
        conn_id: &'a str,
        mailbox: &'a str,
        queue: &'a str,
        sig: &'a str,
    ) -> BoxFut<'a, Vec<Vec<u8>>> {
        Box::pin(async move {
            // 分页取：一次最多 2MiB，避免一个装满的队列把读取上限顶爆。
            // 拿满一页就继续，拿到不满一页说明取完了。
            const PAGE: usize = 2 * 1024 * 1024;
            const MAX_ROUNDS: usize = 64;
            let mut out = Vec::new();
            for _ in 0..MAX_ROUNDS {
                let req = MailboxRequest::queue_get_bounded(queue, sig, PAGE);
                let resp = self.call(conn_id, mailbox, &req).await?;
                let resp = Self::check(resp, "queue_get")?;
                let rows = resp.messages.unwrap_or_default();
                let bytes: usize = rows.iter().map(|m| m.msg.len()).sum();
                let count = rows.len();
                out.extend(rows.into_iter().map(|m| m.msg));
                if count == 0 || bytes < PAGE {
                    break;
                }
            }
            Ok(out)
        })
    }

    fn delete<'a>(
        &'a self,
        conn_id: &'a str,
        mailbox: &'a str,
        queue: &'a str,
        sig: &'a str,
    ) -> BoxFut<'a, ()> {
        Box::pin(async move {
            let req = MailboxRequest::queue_delete(queue, sig);
            let resp = self.call(conn_id, mailbox, &req).await?;
            Self::check(resp, "queue_delete").map(|_| ())
        })
    }
}

pub struct LinkManager {
    store: Arc<Store>,
    api: Arc<dyn QueueApi>,
    links: Mutex<HashMap<String, Link>>,
    /// 可用的 mailbox 池；轮换时依次换一台。
    pool: Mutex<Vec<String>>,
    /// 洋葱是否开着（决定附件分片大小）。
    onion_on: std::sync::atomic::AtomicBool,
}

/// 连续拉取失败多少次就尝试换一台信箱。
const FAILOVER_AFTER: u32 = 3;

/// 邀请有效期：10 分钟。轮换出来的队列不带这个限制。
const INVITE_TTL_MS: u64 = 10 * 60 * 1000;

/// 每多少条消息轮换一次入站队列。
const ROTATE_EVERY: u32 = 500;
/// 帧类型：0 = 文本，1 = 队列轮换通知，2 = 文件分片。
const FRAME_TEXT: u8 = 0;
const FRAME_ROTATE: u8 = 1;
const FRAME_FILE: u8 = 2;

/// 附件上限 2MB。
pub const MAX_FILE_BYTES: usize = 2 * 1024 * 1024;
/// 走洋葱时每片小一点（JSON 数组编码约 4 倍膨胀，单包上限 60KB）。
const FILE_CHUNK_ONION: usize = 8 * 1024 - 64;
/// 直连时每片可以大一些。
const FILE_CHUNK_DIRECT: usize = 24 * 1024;
/// 文件名/MIME 的长度上限。
const FILE_META_MAX: usize = 64;

/// 收到的消息帧。
#[derive(Debug)]
pub enum ReceivedFrame {
    Text(String),
    File {
        name: String,
        mime: String,
        data: Vec<u8>,
    },
}

impl LinkManager {
    /// 洋葱开关：只影响附件分片大小。
    pub fn set_onion_enabled(&self, enabled: bool) {
        self.onion_on
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    pub async fn set_pool(&self, mailboxes: Vec<String>) {
        *self.pool.lock().await = mailboxes;
    }

    pub async fn load(store: Arc<Store>, api: Arc<dyn QueueApi>) -> Result<Self> {
        let rows = store.load_connections()?;
        let mut links = HashMap::new();
        for row in &rows {
            match row_to_link(row) {
                Ok(link) => {
                    links.insert(row.conn_id.clone(), link);
                }
                Err(e) => eprintln!("[links] skip broken connection {}: {e}", row.conn_id),
            }
        }

        // 老版本每进一次「我的」页就建一条待配对连接，可能攒下好几条。
        // 只留最新的一条，其余从库里删掉，队列在后台顺手删（失败就等 TTL）。
        let mut pending: Vec<&ConnRow> = rows
            .iter()
            .filter(|row| state_from_str(&row.state) == LinkState::Pending)
            .collect();
        if pending.len() > 1 {
            pending.sort_by_key(|row| row.created);
            for stale in &pending[..pending.len() - 1] {
                let _ = store.delete_connection(&stale.conn_id);
                links.remove(&stale.conn_id);
                let api = api.clone();
                let conn_id = stale.conn_id.clone();
                let mailbox = stale.in_mailbox.clone();
                let queue = stale.in_queue.clone();
                let owner = stale.owner_sk.clone();
                tokio::spawn(async move {
                    let Ok(owner_sk) = <[u8; 32]>::try_from(owner.as_slice()) else {
                        return;
                    };
                    let Ok(bytes) = connection::hex_decode(&queue) else {
                        return;
                    };
                    let Ok(queue_id) = <[u8; 16]>::try_from(bytes.as_slice()) else {
                        return;
                    };
                    let sig =
                        connection::sign_delete(&queue_id, &SigningKey::from_bytes(&owner_sk));
                    let _ = api.delete(&conn_id, &mailbox, &queue, &sig).await;
                });
            }
        }
        Ok(Self {
            store,
            api,
            links: Mutex::new(links),
            pool: Mutex::new(Vec::new()),
            onion_on: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// 建连接：在 mailbox 上创建接收队列，返回 `(conn_id, 邀请串)`。
    ///
    /// 已经有「还没配对」的连接就直接复用它的邀请——否则每进一次「我的」
    /// 页、每重启一次都会在节点上多留一条没人用的队列。
    pub async fn create(&self, mailbox: &str) -> Result<(String, String)> {
        {
            let links = self.links.lock().await;
            if let Some((conn_id, link)) = links
                .iter()
                .find(|(_, link)| link.state == LinkState::Pending)
            {
                return Ok((conn_id.clone(), link.invite().encode()));
            }
        }
        let (link, invite) = Link::create(mailbox);
        let conn_id = unique_conn_id();
        self.api
            .create(
                &conn_id,
                mailbox,
                &connection::hex_encode(&link.in_queue),
                &link.owner_keys.sender_pub_hex(),
                &link.owner_keys.owner_pub_hex(),
                Some(INVITE_TTL_MS),
            )
            .await?;
        self.persist(&conn_id, &link)?;
        self.links.lock().await.insert(conn_id.clone(), link);
        Ok((conn_id, invite.encode()))
    }

    /// 互扫到对方邀请后配对。
    pub async fn accept(&self, conn_id: &str, invite_text: &str) -> Result<()> {
        let their = Invite::decode(invite_text)?;
        let mut links = self.links.lock().await;
        let link = links
            .get_mut(conn_id)
            .ok_or_else(|| anyhow!("unknown connection {conn_id}"))?;
        link.accept(&their)?;
        self.persist(conn_id, link)?;
        Ok(())
    }

    /// 发一条消息（必须先配对）；到阈值先轮换入站队列。
    pub async fn send(&self, conn_id: &str, plaintext: &[u8]) -> Result<()> {
        self.maybe_rotate(conn_id).await?;

        let mut links = self.links.lock().await;
        let link = links
            .get_mut(conn_id)
            .ok_or_else(|| anyhow!("unknown connection {conn_id}"))?;
        let out = link
            .out
            .clone()
            .ok_or_else(|| anyhow!("connection not paired yet"))?;
        // 帧：类型(1) + 正文；填充后同桶等长。
        let mut frame = Vec::with_capacity(plaintext.len() + 1);
        frame.push(FRAME_TEXT);
        frame.extend_from_slice(plaintext);
        let blob = link.e2e.encrypt(&privchat_common::pad_plaintext(&frame))?;
        link.sent_since_rotate += 1;
        self.persist(conn_id, link)?;
        drop(links);

        let sig = connection::sign_send(
            &out.queue_id,
            &blob,
            &SigningKey::from_bytes(&out.sender_sk),
        );
        self.api
            .send(
                conn_id,
                &out.mailbox,
                &connection::hex_encode(&out.queue_id),
                blob,
                &sig,
            )
            .await
    }

    /// 到阈值就换一条新入站队列（可以换到另一台 mailbox），并通知对方。
    async fn maybe_rotate(&self, conn_id: &str) -> Result<()> {
        let mut links = self.links.lock().await;
        let Some(link) = links.get_mut(conn_id) else {
            return Ok(());
        };
        if !link.user_rotate && link.sent_since_rotate < ROTATE_EVERY {
            return Ok(());
        }
        let Some(out) = link.out.clone() else {
            return Ok(());
        };

        // 选下一台 mailbox：优先换一台，池里只有一台就留在原地。
        let pool = self.pool.lock().await.clone();
        let next_mailbox = if pool.len() > 1 {
            let pos = pool
                .iter()
                .position(|m| m == &link.in_mailbox)
                .map(|i| (i + 1) % pool.len())
                .unwrap_or(0);
            pool[pos].clone()
        } else {
            link.in_mailbox.clone()
        };

        let keys = QueueKeys::generate();
        let mut queue_id = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut queue_id);
        self.api
            .create(
                conn_id,
                &next_mailbox,
                &connection::hex_encode(&queue_id),
                &keys.sender_pub_hex(),
                &keys.owner_pub_hex(),
                None,
            )
            .await?;

        // 把新队列地址告诉对方（走 E2E，别人看不到）。
        let new_out = OutQueue {
            mailbox: next_mailbox.clone(),
            queue_id,
            sender_sk: keys.sender.to_bytes(),
        };
        let body = serde_json::to_vec(&new_out)?;
        let mut frame = Vec::with_capacity(body.len() + 1);
        frame.push(FRAME_ROTATE);
        frame.extend_from_slice(&body);
        let blob = link.e2e.encrypt(&privchat_common::pad_plaintext(&frame))?;
        let sig = connection::sign_send(
            &out.queue_id,
            &blob,
            &SigningKey::from_bytes(&out.sender_sk),
        );
        if let Err(err) = self
            .api
            .send(
                conn_id,
                &out.mailbox,
                &connection::hex_encode(&out.queue_id),
                blob,
                &sig,
            )
            .await
        {
            // 通知没送出去：把刚建的新队列删掉，别在节点上留孤儿占配额。
            let sig = connection::sign_delete(&queue_id, &keys.owner);
            let _ = self
                .api
                .delete(
                    conn_id,
                    &next_mailbox,
                    &connection::hex_encode(&queue_id),
                    &sig,
                )
                .await;
            return Err(err);
        }

        // 旧队列转入排空列表，新队列接管。
        let old = std::mem::replace(&mut link.in_queue, queue_id);
        let old_mailbox = std::mem::replace(&mut link.in_mailbox, next_mailbox);
        let old_keys = std::mem::replace(&mut link.owner_keys, keys);
        link.draining.push(DrainingQueue {
            mailbox: old_mailbox,
            queue_id: old,
            keys: old_keys,
            polls_left: 3,
        });
        link.sent_since_rotate = 0;
        link.user_rotate = false;
        self.persist(conn_id, link)?;
        Ok(())
    }

    /// 手动触发一次轮换。
    pub async fn rotate(&self, conn_id: &str) -> Result<()> {
        {
            let mut links = self.links.lock().await;
            let link = links
                .get_mut(conn_id)
                .ok_or_else(|| anyhow!("unknown connection {conn_id}"))?;
            link.user_rotate = true;
        }
        self.maybe_rotate(conn_id).await
    }

    /// 发一个附件（≤2MB）：切成分片、逐片加密投递。
    ///
    /// 走洋葱时分片小一点（单包上限），直连时可以大一些。
    pub async fn send_file(
        &self,
        conn_id: &str,
        name: &str,
        mime: &str,
        data: &[u8],
    ) -> Result<()> {
        if data.len() > MAX_FILE_BYTES {
            return Err(anyhow!("附件不能超过 2MB"));
        }
        if name.len() > FILE_META_MAX || mime.len() > FILE_META_MAX {
            return Err(anyhow!("文件名或类型太长"));
        }
        let onion_on = self.onion_on.load(std::sync::atomic::Ordering::Relaxed);
        let chunk = if onion_on {
            FILE_CHUNK_ONION
        } else {
            FILE_CHUNK_DIRECT
        };

        let mut links = self.links.lock().await;
        let link = links
            .get_mut(conn_id)
            .ok_or_else(|| anyhow!("unknown connection {conn_id}"))?;
        let out = link
            .out
            .clone()
            .ok_or_else(|| anyhow!("connection not paired yet"))?;

        let mut file_id = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut file_id);
        let total = data.len().div_ceil(chunk).max(1) as u16;

        for seq in 0..total {
            let start = seq as usize * chunk;
            let end = (start + chunk).min(data.len());
            let mut frame = Vec::with_capacity(end - start + 128);
            frame.push(FRAME_FILE);
            frame.extend_from_slice(&file_id);
            frame.extend_from_slice(&seq.to_le_bytes());
            frame.extend_from_slice(&total.to_le_bytes());
            if seq == 0 {
                frame.push(name.len() as u8);
                frame.push(mime.len() as u8);
                frame.extend_from_slice(name.as_bytes());
                frame.extend_from_slice(mime.as_bytes());
            }
            frame.extend_from_slice(&data[start..end]);
            let blob = link.e2e.encrypt(&privchat_common::pad_plaintext(&frame))?;
            let sig = connection::sign_send(
                &out.queue_id,
                &blob,
                &SigningKey::from_bytes(&out.sender_sk),
            );
            self.api
                .send(
                    conn_id,
                    &out.mailbox,
                    &connection::hex_encode(&out.queue_id),
                    blob,
                    &sig,
                )
                .await?;
        }
        link.sent_since_rotate = link.sent_since_rotate.saturating_add(total as u32);
        self.persist(conn_id, link)?;
        Ok(())
    }

    /// 删除连接：本地状态、数据库行、节点上的队列（含排空中的旧队列）。
    pub async fn delete(&self, conn_id: &str) -> Result<()> {
        let link = {
            let mut links = self.links.lock().await;
            links
                .remove(conn_id)
                .ok_or_else(|| anyhow!("unknown connection {conn_id}"))?
        };

        // 节点上的队列尽力删掉（删不掉也不挡本地删除，等 TTL 收尸）。
        let mut queues: Vec<([u8; 16], String, SigningKey)> = vec![(
            link.in_queue,
            link.in_mailbox.clone(),
            link.owner_keys.owner.clone(),
        )];
        for drained in &link.draining {
            queues.push((
                drained.queue_id,
                drained.mailbox.clone(),
                drained.keys.owner.clone(),
            ));
        }
        for (queue_id, mailbox, owner) in queues {
            let sig = connection::sign_delete(&queue_id, &owner);
            let _ = self
                .api
                .delete(conn_id, &mailbox, &connection::hex_encode(&queue_id), &sig)
                .await;
        }

        self.store.delete_connection(conn_id)?;
        Ok(())
    }

    /// 取走并解密本连接入站队列（含轮换中的旧队列）的全部消息。
    pub async fn poll(&self, conn_id: &str) -> Result<Vec<ReceivedFrame>> {
        let (mut sources, had_draining) = {
            let links = self.links.lock().await;
            let link = links
                .get(conn_id)
                .ok_or_else(|| anyhow!("unknown connection {conn_id}"))?;
            let mut src = vec![(
                link.in_mailbox.clone(),
                link.in_queue,
                connection::sign_get(&link.in_queue, &link.owner_keys.owner),
            )];
            for d in &link.draining {
                src.push((
                    d.mailbox.clone(),
                    d.queue_id,
                    connection::sign_get(&d.queue_id, &d.keys.owner),
                ));
            }
            (src, !link.draining.is_empty())
        };

        let mut blobs = Vec::new();
        let mut empty: Vec<[u8; 16]> = Vec::new();
        let mut primary_failed = false;
        for (index, (mailbox, queue, sig)) in sources.drain(..).enumerate() {
            match self
                .api
                .get(conn_id, &mailbox, &connection::hex_encode(&queue), &sig)
                .await
            {
                Ok(mut rows) => {
                    if rows.is_empty() {
                        empty.push(queue);
                    }
                    blobs.append(&mut rows);
                }
                Err(e) => {
                    // 只统计主队列：排空中的旧队列失败不影响判断。
                    if index == 0 {
                        primary_failed = true;
                    }
                    eprintln!("[links] get from {mailbox} failed: {e}");
                }
            }
        }

        let mut out = Vec::new();
        let mut links = self.links.lock().await;
        let link = links
            .get_mut(conn_id)
            .ok_or_else(|| anyhow!("unknown connection {conn_id}"))?;

        // 主队列连续拉不动：累计失败次数，够了就换个信箱再来。
        if primary_failed {
            link.fail_streak = link.fail_streak.saturating_add(1);
        } else {
            link.fail_streak = 0;
        }
        let want_failover = link.fail_streak >= FAILOVER_AFTER;
        let current_mailbox = link.in_mailbox.clone();

        // 旧的排空队列：连续几次没消息就删掉。
        if had_draining {
            for d in link.draining.iter_mut() {
                if empty.contains(&d.queue_id) {
                    d.polls_left = d.polls_left.saturating_sub(1);
                } else {
                    d.polls_left = 3;
                }
            }
            let (drop, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut link.draining)
                .into_iter()
                .partition(|d| d.polls_left == 0);
            link.draining = keep;
            for d in drop {
                let sig = connection::sign_delete(&d.queue_id, &d.keys.owner);
                if let Err(e) = self
                    .api
                    .delete(
                        conn_id,
                        &d.mailbox,
                        &connection::hex_encode(&d.queue_id),
                        &sig,
                    )
                    .await
                {
                    eprintln!("[links] delete drained queue failed: {e}");
                }
            }
        }

        for blob in blobs {
            let plain = match link.e2e.decrypt(&blob) {
                Ok(p) => privchat_common::unpad_plaintext(&p),
                Err(e) => {
                    eprintln!("[links] decrypt failed: {e}");
                    continue;
                }
            };
            match plain.first().copied() {
                Some(FRAME_TEXT) => out.push(ReceivedFrame::Text(
                    String::from_utf8_lossy(&plain[1..]).into_owned(),
                )),
                Some(FRAME_ROTATE) => match serde_json::from_slice::<OutQueue>(&plain[1..]) {
                    Ok(new_out) => {
                        link.out = Some(new_out);
                        self.persist(conn_id, link)?;
                    }
                    Err(e) => eprintln!("[links] bad rotate frame: {e}"),
                },
                Some(FRAME_FILE) => {
                    if let Some(frame) = parse_file_chunk(&plain[1..]) {
                        let partial =
                            link.incoming
                                .entry(frame.id)
                                .or_insert_with(|| PartialFile {
                                    name: String::new(),
                                    mime: String::new(),
                                    total: frame.total,
                                    next: 0,
                                    data: Vec::new(),
                                });
                        if frame.seq == 0 {
                            partial.name = frame.name;
                            partial.mime = frame.mime;
                            partial.total = frame.total;
                            partial.data.clear();
                            partial.next = 0;
                        }
                        if frame.seq == partial.next {
                            partial.data.extend_from_slice(&frame.data);
                            partial.next += 1;
                        }
                        if partial.next == partial.total {
                            if let Some(done) = link.incoming.remove(&frame.id) {
                                out.push(ReceivedFrame::File {
                                    name: done.name,
                                    mime: done.mime,
                                    data: done.data,
                                });
                            }
                        }
                    }
                }
                _ => eprintln!("[links] unknown frame type"),
            }
        }
        self.persist(conn_id, link)?;
        drop(links);

        // 换一台信箱：池里得有别的节点才算有意义。
        if want_failover {
            let pool = self.pool.lock().await.clone();
            let has_other = pool.iter().any(|m| m != &current_mailbox);
            if has_other {
                eprintln!(
                    "[links] {} unreachable {} times, rotating to another mailbox",
                    conn_id, FAILOVER_AFTER
                );
                if let Err(e) = self.rotate(conn_id).await {
                    eprintln!("[links] failover rotate failed: {e}");
                }
            }
        }
        Ok(out)
    }

    /// 全部连接：`(conn_id, 备注, 状态)`。
    pub async fn list(&self) -> Vec<(String, Option<String>, LinkState)> {
        let names: HashMap<String, Option<String>> = self
            .store
            .load_connections()
            .unwrap_or_default()
            .into_iter()
            .map(|row| (row.conn_id, row.name))
            .collect();
        let links = self.links.lock().await;
        let mut out: Vec<_> = links
            .iter()
            .map(|(id, link)| (id.clone(), names.get(id).cloned().flatten(), link.state))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    pub fn rename(&self, conn_id: &str, name: Option<&str>) -> Result<()> {
        self.store.rename_connection(conn_id, name)
    }

    fn persist(&self, conn_id: &str, link: &Link) -> Result<()> {
        let (owner_sk, _) = link.owner_keys.to_bytes();
        let out = link.out.clone();
        let row = ConnRow {
            conn_id: conn_id.to_string(),
            name: None,
            state: state_str(link.state).to_string(),
            in_queue: connection::hex_encode(&link.in_queue),
            in_mailbox: link.in_mailbox.clone(),
            out_queue: out.as_ref().map(|q| connection::hex_encode(&q.queue_id)),
            out_mailbox: out.as_ref().map(|q| q.mailbox.clone()),
            out_sender_sk: out.as_ref().map(|q| q.sender_sk.to_vec()),
            owner_sk: owner_sk.to_vec(),
            e2e_state: link.e2e.to_bytes(),
            created: link.created,
            draining: draining_to_json(&link.draining),
        };
        self.store.save_connection(&row)
    }
}

fn state_str(state: LinkState) -> &'static str {
    match state {
        LinkState::Pending => "pending",
        LinkState::Established => "established",
    }
}

fn state_from_str(s: &str) -> LinkState {
    match s {
        "established" => LinkState::Established,
        _ => LinkState::Pending,
    }
}

fn row_to_link(row: &ConnRow) -> Result<Link> {
    let e2e = E2e::from_bytes(&row.e2e_state)?;
    let in_queue: [u8; 16] = connection::hex_decode(&row.in_queue)?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("bad in_queue"))?;
    let owner_sk: [u8; 32] = row
        .owner_sk
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("bad owner_sk"))?;
    let out = match (&row.out_queue, &row.out_mailbox, &row.out_sender_sk) {
        (Some(q), Some(m), Some(sk)) => Some(OutQueue {
            mailbox: m.clone(),
            queue_id: connection::hex_decode(q)?
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("bad out_queue"))?,
            sender_sk: sk
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("bad out_sender_sk"))?,
        }),
        _ => None,
    };
    Ok(Link {
        in_queue,
        in_mailbox: row.in_mailbox.clone(),
        owner_keys: QueueKeys::from_bytes([0u8; 32], owner_sk),
        out,
        e2e,
        state: state_from_str(&row.state),
        sent_since_rotate: 0,
        user_rotate: false,
        draining: draining_from_json(&row.draining),
        created: row.created,
        fail_streak: 0,
        incoming: std::collections::HashMap::new(),
    })
}

/// 排空队列的持久化形态（JSON 存在 connections.draining）。
#[derive(serde::Serialize, serde::Deserialize)]
struct DrainingRecord {
    mailbox: String,
    queue_id: String,
    owner_sk: String,
    polls_left: u32,
}

fn draining_to_json(queues: &[DrainingQueue]) -> String {
    let list: Vec<DrainingRecord> = queues
        .iter()
        .map(|q| DrainingRecord {
            mailbox: q.mailbox.clone(),
            queue_id: connection::hex_encode(&q.queue_id),
            owner_sk: connection::hex_encode(&q.keys.owner.to_bytes()),
            polls_left: q.polls_left,
        })
        .collect();
    serde_json::to_string(&list).unwrap_or_else(|_| "[]".to_string())
}

/// 解析失败就当成空列表：排空的只是旧队列，宁可少删也不能让连接加载不出来。
fn draining_from_json(text: &str) -> Vec<DrainingQueue> {
    let Ok(list) = serde_json::from_str::<Vec<DrainingRecord>>(text) else {
        return Vec::new();
    };
    list.into_iter()
        .filter_map(|r| {
            let queue_id: [u8; 16] = connection::hex_decode(&r.queue_id)
                .ok()?
                .as_slice()
                .try_into()
                .ok()?;
            let owner: [u8; 32] = connection::hex_decode(&r.owner_sk)
                .ok()?
                .as_slice()
                .try_into()
                .ok()?;
            Some(DrainingQueue {
                mailbox: r.mailbox,
                queue_id,
                // 排空只需要 owner 钥（读/删），sender 钥没有用处。
                keys: QueueKeys::from_bytes([0u8; 32], owner),
                polls_left: r.polls_left,
            })
        })
        .collect()
}

struct FileChunk {
    id: [u8; 16],
    seq: u16,
    total: u16,
    name: String,
    mime: String,
    data: Vec<u8>,
}

/// 解析一个文件分片帧（已去掉帧类型字节）。
fn parse_file_chunk(body: &[u8]) -> Option<FileChunk> {
    if body.len() < 20 {
        return None;
    }
    let id: [u8; 16] = body[..16].try_into().ok()?;
    let seq = u16::from_le_bytes([body[16], body[17]]);
    let total = u16::from_le_bytes([body[18], body[19]]);
    if total == 0 || seq >= total {
        return None;
    }
    let mut pos = 20;
    let (name, mime) = if seq == 0 {
        let name_len = *body.get(pos)? as usize;
        let mime_len = *body.get(pos + 1)? as usize;
        pos += 2;
        let name = String::from_utf8(body.get(pos..pos + name_len)?.to_vec()).ok()?;
        pos += name_len;
        let mime = String::from_utf8(body.get(pos..pos + mime_len)?.to_vec()).ok()?;
        pos += mime_len;
        (name, mime)
    } else {
        (String::new(), String::new())
    };
    Some(FileChunk {
        id,
        seq,
        total,
        name,
        mime,
        data: body.get(pos..)?.to_vec(),
    })
}

fn is_peer_id(id: &str) -> bool {
    id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit())
}

/// 抽样权重：分数越低（越快 / 优先级越高）越容易被抽中。
fn relay_weight(relay: &OnionRelay, weight: f64, latencies: &HashMap<String, u64>) -> f64 {
    let score = crate::layers::app::routing_score(
        relay.priority,
        latencies.get(&relay.peer_id).copied(),
        weight,
    );
    // +0.05 防止除零；分数最低的节点权重最大。
    1.0 / (score + 0.05)
}

/// 按权重不放回地抽 `hops` 个中继。
fn sample_relays(
    pool: &[OnionRelay],
    hops: usize,
    weight: f64,
    latencies: &HashMap<String, u64>,
) -> Vec<String> {
    if pool.is_empty() {
        return Vec::new();
    }
    let mut remaining: Vec<OnionRelay> = pool.to_vec();
    let want = hops.clamp(1, 5).min(remaining.len());
    let mut out = Vec::with_capacity(want);
    while out.len() < want {
        let weights: Vec<f64> = remaining
            .iter()
            .map(|relay| relay_weight(relay, weight, latencies))
            .collect();
        let total: f64 = weights.iter().sum();
        // 取 [0, total) 上的一点，落进哪段就选谁。
        let point =
            (rand_core::RngCore::next_u64(&mut rand_core::OsRng) as f64 / u64::MAX as f64) * total;
        let mut acc = 0.0;
        let mut chosen = remaining.len() - 1;
        for (i, w) in weights.iter().enumerate() {
            acc += w;
            if point <= acc {
                chosen = i;
                break;
            }
        }
        out.push(remaining.remove(chosen).peer_id);
    }
    out
}

fn unique_conn_id() -> String {
    let mut b = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
    connection::hex_encode(&b)
}

#[cfg(test)]
mod tests;
