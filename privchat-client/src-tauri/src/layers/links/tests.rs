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
        _ttl_ms: Option<u64>,
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

/// 只取文本帧，方便断言。
fn texts(frames: Vec<ReceivedFrame>) -> Vec<String> {
    frames
        .into_iter()
        .filter_map(|frame| match frame {
            ReceivedFrame::Text(text) => Some(text),
            _ => None,
        })
        .collect()
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
    assert_eq!(
        texts(a.poll(&a_id).await.unwrap()),
        vec!["hi new queue".to_string()]
    );

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
    assert_eq!(texts(got), vec!["hello from a".to_string()]);

    b.send(&b_id, b"hi from b").await.expect("b send");
    let got = a.poll(&a_id).await.expect("a poll");
    assert_eq!(texts(got), vec!["hi from b".to_string()]);

    // 取回即删。
    assert!(texts(a.poll(&a_id).await.unwrap()).is_empty());
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

/// 反复进「我的」页只应复用同一个邀请，不能每次都在节点上新建队列。
#[tokio::test]
async fn create_reuses_pending_invite() {
    let api = Arc::new(MemQueues::default());
    let a = manager(api.clone() as Arc<dyn QueueApi>, "reuse").await;

    let (id1, invite1) = a.create("m1").await.expect("first create");
    let (id2, invite2) = a.create("m1").await.expect("second create");
    assert_eq!(id1, id2, "pending connection should be reused");
    assert_eq!(invite1, invite2, "invite text should be stable");
    assert_eq!(
        api.queues.lock().unwrap().len(),
        1,
        "only one queue should exist"
    );

    // 配对之后再来一次，应该建新的一条（旧的那条已经用掉了）。
    let b = manager(api.clone() as Arc<dyn QueueApi>, "reuse-b").await;
    let (b_id, b_invite) = b.create("m1").await.expect("b create");
    a.accept(&id1, &b_invite).await.expect("a accept");
    b.accept(&b_id, &invite1).await.expect("b accept");

    let (id3, _) = a.create("m1").await.expect("create after pairing");
    assert_ne!(id1, id3, "paired connection must not be reused");
}

/// 动态选路：优先级高、延迟低的更容易被抽中；权重为 0 时接近等概率。
#[test]
fn dynamic_path_weights_priority_and_latency() {
    let fast = "aa".repeat(32);
    let slow = "bb".repeat(32);
    let pool = vec![
        OnionRelay {
            peer_id: fast.clone(),
            priority: 9,
        },
        OnionRelay {
            peer_id: slow.clone(),
            priority: 0,
        },
    ];
    let mut latencies = HashMap::new();
    latencies.insert(fast.clone(), 20);
    latencies.insert(slow.clone(), 900);

    let mut fast_hits = 0;
    for _ in 0..200 {
        let path = sample_relays(&pool, 1, 1.0, &latencies);
        if path[0] == fast {
            fast_hits += 1;
        }
    }
    assert!(
        fast_hits > 150,
        "priority+latency should favour the fast node, got {fast_hits}/200"
    );

    // 权重 0：只看优先级，快的仍然优先（优先级高的那台）。
    let mut fast_uniform = 0;
    for _ in 0..400 {
        if sample_relays(&pool, 1, 0.0, &latencies)[0] == fast {
            fast_uniform += 1;
        }
    }
    assert!(
        fast_uniform > 300,
        "weight 0 should follow priority, got {fast_uniform}/400"
    );
}

/// 跳数不会超过池子大小，也不会重复走同一个节点。
#[test]
fn dynamic_path_has_no_duplicates() {
    let pool: Vec<OnionRelay> = (0..3)
        .map(|i| OnionRelay {
            peer_id: format!("{:02x}", i).repeat(32),
            priority: 0,
        })
        .collect();
    let path = sample_relays(&pool, 5, 0.5, &HashMap::new());
    assert_eq!(path.len(), 3, "hops capped by pool size");
    let mut unique = path.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), 3, "no duplicate relay in one path");
}

/// 待配对连接的创建时间要落库：启动清理靠它判断哪条更新。
#[tokio::test]
async fn connection_created_timestamp_survives_reload() {
    let api = Arc::new(MemQueues::default());
    let path = std::env::temp_dir().join(format!("privchat-links-created-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    let store = Arc::new(Store::open(&path, [3u8; 32]).unwrap());

    let a = LinkManager::load(store.clone(), api.clone() as Arc<dyn QueueApi>)
        .await
        .expect("load");
    let (id, _) = a.create("m1").await.expect("create");
    drop(a);

    let reloaded = LinkManager::load(store, api as Arc<dyn QueueApi>)
        .await
        .expect("reload");
    let links = reloaded.links.lock().await;
    let link = links.get(&id).expect("link restored");
    assert!(link.created > 0, "created timestamp must be persisted");
}

/// 主队列连续拉不动时，自动换到池里的另一台信箱。
#[tokio::test]
async fn repeated_get_failures_trigger_failover() {
    let api = Arc::new(MemQueues::default());
    let a = manager(api.clone() as Arc<dyn QueueApi>, "fo-a").await;
    let b = manager(api.clone() as Arc<dyn QueueApi>, "fo-b").await;

    let (a_id, a_invite) = a.create("m1").await.expect("a create");
    let (b_id, b_invite) = b.create("m1").await.expect("b create");
    a.accept(&a_id, &b_invite).await.expect("a accept");
    b.accept(&b_id, &a_invite).await.expect("b accept");

    a.set_pool(vec!["m1".to_string(), "m2".to_string()]).await;

    // 模拟信箱失联：把 a 的入站队列从节点上抹掉。
    let in_hex = connection::hex_encode(&a.links.lock().await[&a_id].in_queue);
    api.queues.lock().unwrap().remove(&in_hex);

    for _ in 0..FAILOVER_AFTER {
        let _ = a.poll(&a_id).await;
    }

    let links = a.links.lock().await;
    let link = &links[&a_id];
    assert_eq!(
        link.in_mailbox, "m2",
        "should fail over to the second mailbox"
    );
    assert_eq!(link.draining.len(), 1, "old queue should go to draining");
}

/// 附件：分片发送、对端拼回原样。
#[tokio::test]
async fn file_transfer_roundtrip() {
    let api = Arc::new(MemQueues::default());
    let a = manager(api.clone() as Arc<dyn QueueApi>, "file-a").await;
    let b = manager(api.clone() as Arc<dyn QueueApi>, "file-b").await;

    let (a_id, a_invite) = a.create("m1").await.expect("a create");
    let (b_id, b_invite) = b.create("m1").await.expect("b create");
    a.accept(&a_id, &b_invite).await.expect("a accept");
    b.accept(&b_id, &a_invite).await.expect("b accept");

    let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    a.send_file(&a_id, "pic.png", "image/png", &payload)
        .await
        .expect("send file");

    let frames = b.poll(&b_id).await.expect("b poll");
    assert_eq!(frames.len(), 1, "one file should be assembled");
    match &frames[0] {
        ReceivedFrame::File { name, mime, data } => {
            assert_eq!(name, "pic.png");
            assert_eq!(mime, "image/png");
            assert_eq!(data, &payload, "payload must survive chunking");
        }
        other => panic!("expected file frame, got {other:?}"),
    }
}

/// 附件拼装上限：超 2MB、分片过多、同时拼太多，都要被丢掉。
#[test]
fn file_assembly_respects_limits() {
    let (mut link, _invite) = crate::layers::connection::Link::create("mb");

    let frame = |id: [u8; 16], seq: u16, total: u16, len: usize| FileChunk {
        id,
        seq,
        total,
        name: "x".into(),
        mime: "application/octet-stream".into(),
        data: vec![0u8; len],
    };

    // 1MB × 3 片 = 3MB，超过 2MB 上限 → 拼到第三片时整份丢掉
    let big = [1u8; 16];
    assert!(accept_file_chunk(&mut link, frame(big, 0, 3, 1024 * 1024)).is_none());
    assert!(accept_file_chunk(&mut link, frame(big, 1, 3, 1024 * 1024)).is_none());
    assert!(accept_file_chunk(&mut link, frame(big, 2, 3, 1024 * 1024)).is_none());
    assert!(
        link.incoming.is_empty(),
        "oversized file must be dropped"
    );

    // 分片数超上限（1024）直接拒
    let many = [2u8; 16];
    assert!(accept_file_chunk(&mut link, frame(many, 0, 2000, 10)).is_none());
    assert!(link.incoming.is_empty());

    // 同时拼装超过 4 个文件 → 第 5 个被拒
    for i in 0..4u8 {
        let mut id = [0u8; 16];
        id[0] = i;
        assert!(accept_file_chunk(&mut link, frame(id, 0, 2, 100)).is_none());
    }
    assert_eq!(link.incoming.len(), 4);
    let mut extra = [9u8; 16];
    extra[0] = 9;
    assert!(accept_file_chunk(&mut link, frame(extra, 0, 2, 100)).is_none());
    assert_eq!(link.incoming.len(), 4, "5th partial must be rejected");

    // 清掉之前占位的半截文件，正常的小文件还是能拼完
    link.incoming.clear();
    let ok = [7u8; 16];
    assert!(accept_file_chunk(&mut link, frame(ok, 0, 2, 100)).is_none());
    assert!(accept_file_chunk(&mut link, frame(ok, 1, 2, 100)).is_some());
}

/// 发送端也不许超过 2MB。
#[tokio::test]
async fn send_file_rejects_oversized() {
    let api = Arc::new(MemQueues::default());
    let a = manager(api.clone() as Arc<dyn QueueApi>, "file-big").await;
    let (_, _invite) = a.create("m1").await.expect("create");
    // 没配对也会先撞上大小检查
    let too_big = vec![0u8; MAX_FILE_BYTES + 1];
    assert!(a
        .send_file("whatever", "big.bin", "application/octet-stream", &too_big)
        .await
        .is_err());
}
