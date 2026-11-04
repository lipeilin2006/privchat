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

    fn delete<'a>(
        &'a self,
        _conn_id: &'a str,
        _mailbox: &'a str,
        queue: &'a str,
        sig: &'a str,
    ) -> BoxFut<'a, ()> {
        Box::pin(async move {
            let qid: [u8; 16] = connection::hex_decode(queue)?
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("bad queue"))?;
            let mut q = self.queues.lock().unwrap();
            let item = q.get(queue).ok_or_else(|| anyhow!("no queue"))?;
            if !connection::verify(&item.owner_pub, connection::DOMAIN_DELETE, &qid, None, sig) {
                return Err(anyhow!("bad signature"));
            }
            q.remove(queue);
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
    let path = std::env::temp_dir().join(format!("privchat-links-{dir}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    let store = Arc::new(Store::open(&path, [3u8; 32]).unwrap());
    LinkManager::load(store, api).await.expect("load links")
}

#[tokio::test]
async fn queue_rotation_switches_mailbox() {
    let api = Arc::new(MemQueues::default());
    let a = manager(api.clone() as Arc<dyn QueueApi>, "ra").await;
    let b = manager(api.clone() as Arc<dyn QueueApi>, "rb").await;
    let (a_id, a_invite) = a.create("m1").await.expect("a create");
    let (b_id, b_invite) = b.create("m1").await.expect("b create");
    a.accept(&a_id, &b_invite).await.expect("a accept");
    b.accept(&b_id, &a_invite).await.expect("b accept");

    // 两台 mailbox 的池子：轮换时切到第二台。
    a.set_pool(vec!["m1".to_string(), "m2".to_string()]).await;
    a.rotate(&a_id).await.expect("rotate");

    // A 的入站队列应该已经切到 m2。
    {
        let links = a.links.lock().await;
        let link = links.get(&a_id).expect("link");
        assert_eq!(link.in_mailbox, "m2");
        assert_eq!(link.draining.len(), 1);
    }

    // B 取一次，收到轮换通知，把出站队列切到 A 的新队列。
    let _ = b.poll(&b_id).await.expect("b poll");
    b.send(&b_id, b"hi new queue").await.expect("b send");
    assert_eq!(a.poll(&a_id).await.unwrap(), vec![b"hi new queue".to_vec()]);

    // 旧队列连续几次没消息后应被删除。
    let old_queue = a.links.lock().await[&a_id].draining[0].queue_id;
    let old_hex = connection::hex_encode(&old_queue);
    for _ in 0..4 {
        let _ = a.poll(&a_id).await.expect("poll drain");
    }
    assert!(
        !api.queues.lock().unwrap().contains_key(&old_hex),
        "old queue must be deleted after draining"
    );
}

#[tokio::test]
async fn auto_rotation_after_threshold() {
    let api = Arc::new(MemQueues::default());
    let a = manager(api.clone() as Arc<dyn QueueApi>, "aa").await;
    let b = manager(api as Arc<dyn QueueApi>, "ab").await;
    let (a_id, a_invite) = a.create("m1").await.expect("a create");
    let (b_id, b_invite) = b.create("m1").await.expect("b create");
    a.accept(&a_id, &b_invite).await.expect("a accept");
    b.accept(&b_id, &a_invite).await.expect("b accept");

    for i in 0..=(ROTATE_EVERY as usize) {
        a.send(&a_id, format!("m{i}").as_bytes())
            .await
            .expect("send");
    }
    // 阈值到了自动轮换：旧队列进排空列表。
    let draining = {
        let links = a.links.lock().await;
        links[&a_id].draining.len()
    };
    assert_eq!(
        draining, 1,
        "expected one rotation after {} sends",
        ROTATE_EVERY
    );
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

/// 轮换后重启：排空列表必须跟着连接一起回来，否则旧队列里的消息永远没人取。
#[tokio::test]
async fn draining_queues_survive_restart() {
    let api = Arc::new(MemQueues::default());
    let path = std::env::temp_dir().join(format!("privchat-links-drain-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    let store = Arc::new(Store::open(&path, [3u8; 32]).unwrap());

    let a = LinkManager::load(store.clone(), api.clone() as Arc<dyn QueueApi>)
        .await
        .expect("load a");
    let b = manager(api.clone() as Arc<dyn QueueApi>, "drain-b").await;

    let (a_id, a_invite) = a.create("m1").await.expect("a create");
    let (b_id, b_invite) = b.create("m1").await.expect("b create");
    a.accept(&a_id, &b_invite).await.expect("a accept");
    b.accept(&b_id, &a_invite).await.expect("b accept");

    a.set_pool(vec!["m1".to_string(), "m2".to_string()]).await;
    a.rotate(&a_id).await.expect("rotate");
    let old_hex = {
        let links = a.links.lock().await;
        assert_eq!(links[&a_id].draining.len(), 1);
        connection::hex_encode(&links[&a_id].draining[0].queue_id)
    };
    drop(a);

    // 重新加载：排空队列应该还在。
    let a2 = LinkManager::load(store, api.clone() as Arc<dyn QueueApi>)
        .await
        .expect("reload a");
    {
        let links = a2.links.lock().await;
        let link = links.get(&a_id).expect("link restored");
        assert_eq!(link.draining.len(), 1, "draining queue lost on reload");
        assert_eq!(connection::hex_encode(&link.draining[0].queue_id), old_hex);
        assert_eq!(link.draining[0].polls_left, 3);
    }

    // 继续排空：几次空轮询之后旧队列按 owner 签名删掉。
    for _ in 0..4 {
        let _ = a2.poll(&a_id).await.expect("poll drain after reload");
    }
    assert!(
        !api.queues.lock().unwrap().contains_key(&old_hex),
        "restored draining queue must still be deletable"
    );
}
