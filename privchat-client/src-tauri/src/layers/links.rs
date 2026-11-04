//! 连接管理：把 `connection::Link` 与 mailbox 的队列原语接起来。
//!
//! 一条连接 = 两条单向队列；本模块负责建队列、发消息、轮询解密与落库。
//! 队列的读写权限由签名保证，和 TLS 身份无关，所以每个连接用一条**临时**
//! 拨号身份即可（每次启动重新生成，反而少了长期关联）。

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;
use iroh::Endpoint;
use tokio::sync::Mutex;

use crate::layers::connection::{self, Invite, Link, LinkState, OutQueue, QueueKeys};
use crate::layers::crypto::connection::Connection as E2e;
use crate::layers::mailbox::MailboxClient;
use crate::layers::store::{ConnRow, Store};
use crate::layers::transport::Transport;

pub struct LinkManager {
    transport: Transport,
    store: Arc<Store>,
    links: Mutex<HashMap<String, Link>>,
    /// 每个连接一条临时拨号端点（队列权限靠签名，不靠 TLS 身份）。
    endpoints: Mutex<HashMap<String, Endpoint>>,
}

impl LinkManager {
    pub async fn load(transport: Transport, store: Arc<Store>) -> Result<Self> {
        let mut links = HashMap::new();
        for row in store.load_connections()? {
            match row_to_link(&row) {
                Ok(link) => {
                    links.insert(row.conn_id.clone(), link);
                }
                Err(e) => eprintln!("[links] skip broken connection {}: {e}", row.conn_id),
            }
        }
        Ok(Self {
            transport,
            store,
            links: Mutex::new(links),
            endpoints: Mutex::new(HashMap::new()),
        })
    }

    /// 建连接：在 mailbox 上创建接收队列，返回 `(conn_id, 邀请串)`。
    pub async fn create(&self, mailbox: &str) -> Result<(String, String)> {
        let (link, invite) = Link::create(mailbox);
        let endpoint = self.endpoint_for("new").await?;
        MailboxClient::queue_create(
            &endpoint,
            mailbox,
            &connection::hex_encode(&link.in_queue),
            &link.owner_keys.sender_pub_hex(),
            &link.owner_keys.owner_pub_hex(),
        )
        .await?;

        let conn_id = unique_conn_id();
        self.persist(&conn_id, &link)?;
        self.links.lock().await.insert(conn_id.clone(), link);
        Ok((conn_id, invite.encode()))
    }

    /// 互扫到对方的邀请后配对。
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

    /// 发一条消息（必须有出站队列）。
    pub async fn send(&self, conn_id: &str, plaintext: &[u8]) -> Result<()> {
        let mut links = self.links.lock().await;
        let link = links
            .get_mut(conn_id)
            .ok_or_else(|| anyhow!("unknown connection {conn_id}"))?;
        let out = link
            .out
            .clone()
            .ok_or_else(|| anyhow!("connection not paired yet"))?;
        let blob = link.e2e.encrypt(plaintext)?;
        self.persist(conn_id, link)?;
        drop(links);
        let endpoint = self.endpoint(conn_id).await?;
        send_blob(&endpoint, &out, &blob).await
    }

    /// 取走并解密本连接入站队列的全部消息。
    pub async fn poll(&self, conn_id: &str) -> Result<Vec<Vec<u8>>> {
        let (mailbox, queue, sig, state) = {
            let links = self.links.lock().await;
            let link = links
                .get(conn_id)
                .ok_or_else(|| anyhow!("unknown connection {conn_id}"))?;
            (
                link.in_mailbox.clone(),
                link.in_queue,
                connection::sign_get(&link.in_queue, &link.owner_keys.owner),
                link.state,
            )
        };
        let endpoint = self.endpoint(conn_id).await?;
        let rows =
            MailboxClient::queue_get(&endpoint, &mailbox, &connection::hex_encode(&queue), &sig)
                .await?;

        let mut out = Vec::new();
        let mut links = self.links.lock().await;
        let link = links
            .get_mut(conn_id)
            .ok_or_else(|| anyhow!("unknown connection {conn_id}"))?;
        for row in rows {
            match link.e2e.decrypt(&row.msg) {
                Ok(plain) => {
                    let _ = state;
                    out.push(plain);
                }
                Err(e) => eprintln!("[links] decrypt failed: {e}"),
            }
        }
        self.persist(conn_id, link)?;
        Ok(out)
    }

    pub async fn ids(&self) -> Vec<String> {
        self.links.lock().await.keys().cloned().collect()
    }

    pub async fn state(&self, conn_id: &str) -> Option<LinkState> {
        self.links.lock().await.get(conn_id).map(|l| l.state)
    }

    /// 给连接备注（只是显示名，不影响任何密钥）。
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
            created: 0,
            last_used: 0,
        };
        self.store.save_connection(&row)
    }

    async fn endpoint_for(&self, _tag: &str) -> Result<Endpoint> {
        let local_id = self.transport.create_identity().await?;
        self.transport.endpoint_for(&local_id).await
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
}

async fn send_blob(endpoint: &Endpoint, out: &OutQueue, blob: &[u8]) -> Result<()> {
    let sig = connection::sign_send(&out.queue_id, blob, &SigningKey::from_bytes(&out.sender_sk));
    MailboxClient::queue_send(
        endpoint,
        &out.mailbox,
        &connection::hex_encode(&out.queue_id),
        blob.to_vec(),
        &sig,
    )
    .await
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
        owner_keys: QueueKeys::from_bytes([0u8; 32], owner_sk),
        in_queue,
        in_mailbox: row.in_mailbox.clone(),
        out,
        e2e,
        state: state_from_str(&row.state),
    })
}

fn unique_conn_id() -> String {
    let mut b = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
    connection::hex_encode(&b)
}
