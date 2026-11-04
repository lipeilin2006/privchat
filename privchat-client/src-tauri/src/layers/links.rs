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

use crate::layers::connection::{self, Invite, Link, LinkState, OutQueue, QueueKeys};
use crate::layers::crypto::connection::Connection as E2e;
use crate::layers::mailbox::MailboxClient;
use crate::layers::store::{ConnRow, Store};
use crate::layers::transport::Transport;

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
}

/// 生产实现：每个连接一条临时拨号端点（队列权限靠签名，不靠 TLS 身份）。
pub struct IrohQueues {
    transport: Transport,
    endpoints: Mutex<HashMap<String, Endpoint>>,
}

impl IrohQueues {
    pub fn new(transport: Transport) -> Self {
        Self {
            transport,
            endpoints: Mutex::new(HashMap::new()),
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
            let ep = self.endpoint(conn_id).await?;
            MailboxClient::queue_create(&ep, mailbox, queue, sender_pub, owner_pub).await
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
            let ep = self.endpoint(conn_id).await?;
            MailboxClient::queue_send(&ep, mailbox, queue, payload, sig).await
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
            let ep = self.endpoint(conn_id).await?;
            let rows = MailboxClient::queue_get(&ep, mailbox, queue, sig).await?;
            Ok(rows.into_iter().map(|m| m.msg).collect())
        })
    }
}

pub struct LinkManager {
    store: Arc<Store>,
    api: Arc<dyn QueueApi>,
    links: Mutex<HashMap<String, Link>>,
}

impl LinkManager {
    pub async fn load(store: Arc<Store>, api: Arc<dyn QueueApi>) -> Result<Self> {
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
            store,
            api,
            links: Mutex::new(links),
        })
    }

    /// 建连接：在 mailbox 上创建接收队列，返回 `(conn_id, 邀请串)`。
    pub async fn create(&self, mailbox: &str) -> Result<(String, String)> {
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

    /// 发一条消息（必须先配对）。
    pub async fn send(&self, conn_id: &str, plaintext: &[u8]) -> Result<()> {
        let mut links = self.links.lock().await;
        let link = links
            .get_mut(conn_id)
            .ok_or_else(|| anyhow!("unknown connection {conn_id}"))?;
        let out = link
            .out
            .clone()
            .ok_or_else(|| anyhow!("connection not paired yet"))?;
        // 加密前做桶填充：同桶消息密文等长，削弱长度侧信道。
        let padded = privchat_common::pad_plaintext(plaintext);
        let blob = link.e2e.encrypt(&padded)?;
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

    /// 取走并解密本连接入站队列的全部消息。
    pub async fn poll(&self, conn_id: &str) -> Result<Vec<Vec<u8>>> {
        let (mailbox, queue, sig) = {
            let links = self.links.lock().await;
            let link = links
                .get(conn_id)
                .ok_or_else(|| anyhow!("unknown connection {conn_id}"))?;
            (
                link.in_mailbox.clone(),
                connection::hex_encode(&link.in_queue),
                connection::sign_get(&link.in_queue, &link.owner_keys.owner),
            )
        };
        let blobs = self.api.get(conn_id, &mailbox, &queue, &sig).await?;

        let mut out = Vec::new();
        let mut links = self.links.lock().await;
        let link = links
            .get_mut(conn_id)
            .ok_or_else(|| anyhow!("unknown connection {conn_id}"))?;
        for blob in blobs {
            match link.e2e.decrypt(&blob) {
                Ok(plain) => out.push(privchat_common::unpad_plaintext(&plain)),
                Err(e) => eprintln!("[links] decrypt failed: {e}"),
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

    pub async fn state(&self, conn_id: &str) -> Option<LinkState> {
        self.links.lock().await.get(conn_id).map(|l| l.state)
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
            created: 0,
            last_used: 0,
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
    })
}

fn unique_conn_id() -> String {
    let mut b = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
    connection::hex_encode(&b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layers::store::Store;
    use std::sync::Mutex as StdMutex;

    #[derive(Default)]
    struct MemQueues {
        queues: StdMutex<HashMap<String, MemQueue>>,
    }

    struct MemQueue {
        sender_pub: [u8; 32],
        owner_pub: [u8; 32],
        msgs: Vec<Vec<u8>>,
    }

    impl QueueApi for MemQueues {
        fn create<'a>(
            &'a self,
            _conn_id: &'a str,
            _mailbox: &'a str,
            queue: &'a str,
            sender_pub: &'a str,
            owner_pub: &'a str,
        ) -> BoxFut<'a, ()> {
            Box::pin(async move {
                let sender: [u8; 32] = connection::hex_decode(sender_pub)?
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow!("bad sender"))?;
                let owner: [u8; 32] = connection::hex_decode(owner_pub)?
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow!("bad owner"))?;
                let mut q = self.queues.lock().unwrap();
                if q.contains_key(queue) {
                    return Err(anyhow!("queue exists"));
                }
                q.insert(
                    queue.to_string(),
                    MemQueue {
                        sender_pub: sender,
                        owner_pub: owner,
                        msgs: Vec::new(),
                    },
                );
                Ok(())
            })
        }

        fn send<'a>(
            &'a self,
            _conn_id: &'a str,
            _mailbox: &'a str,
            queue: &'a str,
            payload: Vec<u8>,
            sig: &'a str,
        ) -> BoxFut<'a, ()> {
            Box::pin(async move {
                let qid: [u8; 16] = connection::hex_decode(queue)?
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow!("bad queue"))?;
                let mut q = self.queues.lock().unwrap();
                let item = q.get_mut(queue).ok_or_else(|| anyhow!("no queue"))?;
                if !connection::verify(
                    &item.sender_pub,
                    connection::DOMAIN_SEND,
                    &qid,
                    Some(&payload),
                    sig,
                ) {
                    return Err(anyhow!("bad signature"));
                }
                item.msgs.push(payload);
                Ok(())
            })
        }

        fn get<'a>(
            &'a self,
            _conn_id: &'a str,
            _mailbox: &'a str,
            queue: &'a str,
            sig: &'a str,
        ) -> BoxFut<'a, Vec<Vec<u8>>> {
            Box::pin(async move {
                let qid: [u8; 16] = connection::hex_decode(queue)?
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow!("bad queue"))?;
                let mut q = self.queues.lock().unwrap();
                let item = q.get_mut(queue).ok_or_else(|| anyhow!("no queue"))?;
                if !connection::verify(&item.owner_pub, connection::DOMAIN_GET, &qid, None, sig) {
                    return Err(anyhow!("bad signature"));
                }
                Ok(std::mem::take(&mut item.msgs))
            })
        }
    }

    async fn manager(api: Arc<dyn QueueApi>, dir: &str) -> LinkManager {
        let path =
            std::env::temp_dir().join(format!("privchat-links-{dir}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        let store = Arc::new(Store::open(&path, [3u8; 32]).unwrap());
        LinkManager::load(store, api).await.expect("load links")
    }

    #[tokio::test]
    async fn mutual_scan_end_to_end() {
        let api = Arc::new(MemQueues::default());
        let a = manager(api.clone() as Arc<dyn QueueApi>, "a").await;
        let b = manager(api as Arc<dyn QueueApi>, "b").await;

        let (a_id, a_invite) = a.create("mb").await.expect("a create");
        let (b_id, b_invite) = b.create("mb").await.expect("b create");
        a.accept(&a_id, &b_invite).await.expect("a accept");
        b.accept(&b_id, &a_invite).await.expect("b accept");

        a.send(&a_id, b"hello from a").await.expect("a send");
        let got = b.poll(&b_id).await.expect("b poll");
        assert_eq!(got, vec![b"hello from a".to_vec()]);

        b.send(&b_id, b"hi from b").await.expect("b send");
        let got = a.poll(&a_id).await.expect("a poll");
        assert_eq!(got, vec![b"hi from b".to_vec()]);

        // 取回即删。
        assert!(a.poll(&a_id).await.unwrap().is_empty());
    }
}
