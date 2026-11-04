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
    self, DrainingQueue, Invite, Link, LinkState, OutQueue, QueueKeys,
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
    ) -> BoxFut<'a, ()> {
        Box::pin(async move {
            let req = MailboxRequest::queue_create(queue, sender_pub, owner_pub);
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
            let req = MailboxRequest::queue_get(queue, sig);
            let resp = self.call(conn_id, mailbox, &req).await?;
            let resp = Self::check(resp, "queue_get")?;
            Ok(resp
                .messages
                .unwrap_or_default()
                .into_iter()
                .map(|m| m.msg)
                .collect())
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
}

/// 每多少条消息轮换一次入站队列。
const ROTATE_EVERY: u32 = 500;
/// 帧类型：0 = 文本，1 = 队列轮换通知。
const FRAME_TEXT: u8 = 0;
const FRAME_ROTATE: u8 = 1;

impl LinkManager {
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

    /// 取走并解密本连接入站队列（含轮换中的旧队列）的全部消息。
    pub async fn poll(&self, conn_id: &str) -> Result<Vec<Vec<u8>>> {
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
        for (mailbox, queue, sig) in sources.drain(..) {
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
                Err(e) => eprintln!("[links] get from {mailbox} failed: {e}"),
            }
        }

        let mut out = Vec::new();
        let mut links = self.links.lock().await;
        let link = links
            .get_mut(conn_id)
            .ok_or_else(|| anyhow!("unknown connection {conn_id}"))?;

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
                Some(FRAME_TEXT) => out.push(plain[1..].to_vec()),
                Some(FRAME_ROTATE) => match serde_json::from_slice::<OutQueue>(&plain[1..]) {
                    Ok(new_out) => {
                        link.out = Some(new_out);
                        self.persist(conn_id, link)?;
                    }
                    Err(e) => eprintln!("[links] bad rotate frame: {e}"),
                },
                _ => eprintln!("[links] unknown frame type"),
            }
        }
        self.persist(conn_id, link)?;
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
            role: "peer".to_string(),
            state: state_str(link.state).to_string(),
            in_queue: connection::hex_encode(&link.in_queue),
            in_mailbox: link.in_mailbox.clone(),
            out_queue: out.as_ref().map(|q| connection::hex_encode(&q.queue_id)),
            out_mailbox: out.as_ref().map(|q| q.mailbox.clone()),
            out_sender_sk: out.as_ref().map(|q| q.sender_sk.to_vec()),
            owner_sk: owner_sk.to_vec(),
            e2e_state: link.e2e.to_bytes(),
            created: link.created,
            last_used: now_ms(),
            draining: draining_to_json(&link.draining),
        };
        self.store.save_connection(&row)
    }
}

fn state_str(state: LinkState) -> &'static str {
    match state {
        LinkState::Pending => "pending",
        LinkState::Established => "established",
        LinkState::Closed => "closed",
    }
}

fn state_from_str(s: &str) -> LinkState {
    match s {
        "pending" | "invited" | "joining" => LinkState::Pending,
        "established" => LinkState::Established,
        _ => LinkState::Closed,
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

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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
