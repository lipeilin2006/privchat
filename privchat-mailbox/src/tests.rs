use super::*;
use crate::store::MailboxStore;

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 单向队列：创建、签名投递、owner 取走、删除。
#[tokio::test]
async fn queue_create_send_get_delete() {
    let dir = std::env::temp_dir().join(format!("privchat-queue-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let store = MailboxStore::open(dir.join("mb.db"), 0).expect("open");
    let _endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(iroh::SecretKey::generate())
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .expect("bind");
    let handler = MailboxHandler { store };

    // 两把独立的 Ed25519 密钥：sender（谁可以写）与 owner（谁能读/删）。
    let sender = ed25519_dalek::SigningKey::from_bytes(&iroh::SecretKey::generate().to_bytes());
    let owner = ed25519_dalek::SigningKey::from_bytes(&iroh::SecretKey::generate().to_bytes());
    use ed25519_dalek::Signer;
    let sender_pub = hex_of(sender.verifying_key().as_bytes());
    let owner_pub = hex_of(owner.verifying_key().as_bytes());
    let queue = "000102030405060708090a0b0c0d0e0f";

    // 创建。
    let resp = handle_request(
        &handler,
        &serde_json::to_vec(&MailboxRequest::queue_create(
            queue,
            &sender_pub,
            &owner_pub,
        ))
        .unwrap(),
    )
    .await;
    assert!(resp.ok, "create: {:?}", resp.error);
    // 重复创建被拒（先到先得）。
    let resp = handle_request(
        &handler,
        &serde_json::to_vec(&MailboxRequest::queue_create(
            queue,
            &sender_pub,
            &owner_pub,
        ))
        .unwrap(),
    )
    .await;
    assert!(!resp.ok, "duplicate create must fail");

    // 投递：签名覆盖 domain || queue || payload。
    let payload = b"queue-ciphertext".to_vec();
    let qid: [u8; 16] = hex_decode(queue).unwrap().as_slice().try_into().unwrap();
    let mut msg = b"privchat/queue/send/v1".to_vec();
    msg.extend_from_slice(&qid);
    msg.extend_from_slice(&payload);
    let sig = hex_of(&sender.sign(&msg).to_bytes());
    let resp = handle_request(
        &handler,
        &serde_json::to_vec(&MailboxRequest::queue_send(queue, payload.clone(), &sig)).unwrap(),
    )
    .await;
    assert!(resp.ok, "send: {:?}", resp.error);

    // 伪造签名被拒。
    let bad_sig = hex_of(&owner.sign(&msg).to_bytes());
    let resp = handle_request(
        &handler,
        &serde_json::to_vec(&MailboxRequest::queue_send(
            queue,
            payload.clone(),
            &bad_sig,
        ))
        .unwrap(),
    )
    .await;
    assert!(!resp.ok, "forged send must fail");

    // 用 sender 身份取走：拒绝（只有 owner 能取）。
    let get_msg = {
        let mut m = b"privchat/queue/get/v1".to_vec();
        m.extend_from_slice(&qid);
        m
    };
    let wrong = hex_of(&sender.sign(&get_msg).to_bytes());
    let resp = handle_request(
        &handler,
        &serde_json::to_vec(&MailboxRequest::queue_get(queue, &wrong)).unwrap(),
    )
    .await;
    assert!(!resp.ok, "sender must not read the queue");

    // owner 取走，返回一条；再取为空（取回即删）。
    let ok_sig = hex_of(&owner.sign(&get_msg).to_bytes());
    let resp = handle_request(
        &handler,
        &serde_json::to_vec(&MailboxRequest::queue_get(queue, &ok_sig)).unwrap(),
    )
    .await;
    assert!(resp.ok, "get: {:?}", resp.error);
    let msgs = resp.messages.expect("messages");
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].msg, payload);

    let resp = handle_request(
        &handler,
        &serde_json::to_vec(&MailboxRequest::queue_get(queue, &ok_sig)).unwrap(),
    )
    .await;
    assert!(resp.ok);
    assert!(resp.messages.expect("messages").is_empty());

    // 删除后队列不存在。
    let del_msg = {
        let mut m = b"privchat/queue/delete/v1".to_vec();
        m.extend_from_slice(&qid);
        m
    };
    let del_sig = hex_of(&owner.sign(&del_msg).to_bytes());
    let resp = handle_request(
        &handler,
        &serde_json::to_vec(&MailboxRequest::queue_delete(queue, &del_sig)).unwrap(),
    )
    .await;
    assert!(resp.ok, "delete: {:?}", resp.error);
    assert!(handler.store.queue_auth(queue).await.unwrap().is_none());
}

/// 单队列容量上限：条数满了再投递应被拒。
#[tokio::test]
async fn queue_capacity_limits() {
    let dir = std::env::temp_dir().join(format!("privchat-qcap-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let store = MailboxStore::open_with_limits(dir.join("mb.db"), 0, 2, 1024, 10).expect("open");
    let q = "00112233445566778899aabbccddeeff";
    assert!(store
        .create_queue(q, &[1u8; 32], &[2u8; 32], 0)
        .await
        .expect("create"));
    assert!(store.push_queue(q, b"a", 0).await.is_ok());
    assert!(store.push_queue(q, b"b", 0).await.is_ok());
    assert!(
        store.push_queue(q, b"c", 0).await.is_err(),
        "third message must be rejected"
    );

    // 取走清空后可以继续写。
    let got = store.take_queue(q).await.expect("take");
    assert_eq!(got.len(), 2);
    assert!(store.push_queue(q, b"d", 0).await.is_ok());
}

/// TTL 清理必须真的删掉队列里的过期密文（表名写错会让它一直静默失败）。
#[tokio::test]
async fn purge_expired_removes_old_messages() {
    let dir = std::env::temp_dir().join(format!("privchat-ttl-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let store = MailboxStore::open_with_limits(dir.join("ttl.db"), 60, 1000, 1 << 20, 10)
        .expect("open store");

    let queue = "00112233445566778899aabbccddeeff";
    store
        .create_queue(queue, &[1u8; 32], &[2u8; 32], 1_000)
        .await
        .expect("create");
    store
        .push_queue(queue, b"old", 1_000)
        .await
        .expect("push old");
    store
        .push_queue(queue, b"fresh", 100_000)
        .await
        .expect("push fresh");

    // 60 秒 TTL：把 1 秒时写入的那条清掉，100 秒的那条留下。
    let removed = store.purge_expired(101_000).await.expect("purge");
    assert_eq!(removed, 1, "expired message must be deleted");

    let left = store.take_queue(queue).await.expect("take");
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].1, b"fresh");
    let _ = std::fs::remove_dir_all(&dir);
}

/// 队列总数有上限：光刷 create 不能把节点磁盘刷满。
#[tokio::test]
async fn queue_capacity_is_capped() {
    let dir = std::env::temp_dir().join(format!("privchat-qcap-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let store =
        MailboxStore::open_with_limits(dir.join("q.db"), 0, 1000, 1 << 20, 2).expect("open");

    for i in 0..2u8 {
        let q = format!("{:032x}", i);
        assert!(store
            .create_queue(&q, &[1u8; 32], &[2u8; 32], 1)
            .await
            .expect("create under cap"));
    }
    let over = store
        .create_queue(
            "00000000000000000000000000000009",
            &[1u8; 32],
            &[2u8; 32],
            1,
        )
        .await;
    assert!(over.is_err(), "create beyond cap must be rejected");
    let _ = std::fs::remove_dir_all(&dir);
}
