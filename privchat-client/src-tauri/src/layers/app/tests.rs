#![allow(unused_variables)]
use super::*;

const TEST_KEY: [u8; 32] = [0x42; 32];

/// 测试辅助：生成一个「带 EndpointTicket」的邀请（no-relay 模式没有 DNS）。
/// 返回 `(peer_id, invite)`。
async fn new_invite(app: &App) -> (String, String) {
    let invite = app.self_ticket().await;
    let (peer, _spk, _, opks) = crypto::parse_invite(&invite).expect("parse invite");
    let secret = app.transport.secret_for(&peer).await.expect("secret");
    let spk_pk = app.transport.spk_public(&peer).await.expect("spk");
    let ticket = app.transport.ticket_for(&peer).await;
    (
        peer,
        crypto::encode_invite(&secret, &spk_pk, Some(&ticket), &opks),
    )
}

/// 全栈集成：两个客户端各自完整走 L4->L1->L4，通过真实 QUIC 交换消息，
/// 验证直连、身份认证与消息贯通。每联系人使用专属身份。
#[tokio::test]
async fn two_clients_roundtrip() {
    let dir_a = std::env::temp_dir().join(format!("privchat-it-a-{}", std::process::id()));
    let dir_b = std::env::temp_dir().join(format!("privchat-it-b-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);

    let (alice, mut rx_a) = App::start_no_relay(dir_a.clone(), TEST_KEY)
        .await
        .expect("start a");
    let (bob, mut rx_b) = App::start_no_relay(dir_b.clone(), TEST_KEY)
        .await
        .expect("start b");

    // 双方互相通过邀请串建立好友关系（no-relay 用带票据的邀请）。
    let (alice_for_bob, alice_invite) = new_invite(&alice).await;
    let (bob_for_alice, bob_invite) = new_invite(&bob).await;

    let bob_id = alice
        .connect_peer(&bob_invite, Some("Bob".into()))
        .await
        .expect("a->b");
    let alice_id = bob.connect_peer(&alice_invite, None).await.expect("b->a");
    assert_eq!(bob_id, bob_for_alice);
    assert_eq!(alice_id, alice_for_bob);

    // Alice -> Bob。
    alice
        .send_message(&bob_id, "hello bob")
        .await
        .expect("alice send");
    let env = rx_b.recv().await.expect("bob envelope");
    let msg = bob
        .handle_incoming(env)
        .await
        .expect("bob recv")
        .expect("text");
    assert_eq!(msg.text, "hello bob");
    assert_eq!(msg.from, alice_for_bob);

    // Bob -> Alice。
    bob.send_message(&alice_id, "hi alice")
        .await
        .expect("bob send");
    let env = rx_a.recv().await.expect("alice envelope");
    let msg = alice
        .handle_incoming(env)
        .await
        .expect("alice recv")
        .expect("text");
    assert_eq!(msg.text, "hi alice");
    assert_eq!(msg.from, bob_for_alice);

    // 清理测试目录。
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

/// 联系人持久化：建立好友关系后重启，双方自动恢复连接并继续通信。
#[tokio::test]
async fn contacts_persist_across_restart() {
    let dir_a = std::env::temp_dir().join(format!("privchat-cp-a-{}", std::process::id()));
    let dir_b = std::env::temp_dir().join(format!("privchat-cp-b-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);

    // 第一轮：建立好友 + 发送一条消息。
    let (alice, _rx_a) = App::start_no_relay(dir_a.clone(), TEST_KEY)
        .await
        .expect("start a");
    let (bob, mut rx_b) = App::start_no_relay(dir_b.clone(), TEST_KEY)
        .await
        .expect("start b");
    let (alice_for_bob, alice_invite) = new_invite(&alice).await;
    let (bob_for_alice, bob_invite) = new_invite(&bob).await;
    let bob_id = alice.connect_peer(&bob_invite, None).await.expect("a->b");
    let alice_id = bob.connect_peer(&alice_invite, None).await.expect("b->a");
    alice
        .send_message(&bob_id, "hello bob")
        .await
        .expect("alice send");
    let env = rx_b.recv().await.expect("bob envelope");
    let msg = bob
        .handle_incoming(env)
        .await
        .expect("bob recv")
        .expect("text");
    assert_eq!(msg.text, "hello bob");

    // 模拟重启：先关闭释放端口，再丢弃内存态。
    alice.close().await;
    bob.close().await;
    drop(alice);
    drop(bob);
    let (alice2, mut rx_a2) = App::start_no_relay(dir_a.clone(), TEST_KEY)
        .await
        .expect("restart a");
    let (bob2, mut rx_b2) = App::start_no_relay(dir_b.clone(), TEST_KEY)
        .await
        .expect("restart b");

    // 重启后联系人自动恢复，且仍用同一专属身份。
    let a_contacts = alice2.list_contacts().await;
    let b_contacts = bob2.list_contacts().await;
    assert_eq!(
        a_contacts
            .iter()
            .map(|c| c.peer_id.as_str())
            .collect::<Vec<_>>(),
        vec![bob_id.as_str()]
    );
    assert_eq!(
        b_contacts
            .iter()
            .map(|c| c.peer_id.as_str())
            .collect::<Vec<_>>(),
        vec![alice_id.as_str()]
    );

    // 消息历史也随重启保留。
    let hist = bob2.get_history(&alice_id).await;
    assert_eq!(hist.len(), 1);
    assert_eq!(hist[0].text, "hello bob");

    // 无需重新扫码：联系人与连接信息都从磁盘恢复，直接继续通信。
    alice2
        .send_message(&bob_id, "still here")
        .await
        .expect("alice2 send");
    let env = rx_b2.recv().await.expect("bob2 envelope");
    let msg = bob2
        .handle_incoming(env)
        .await
        .expect("bob2 recv")
        .expect("text");
    assert_eq!(msg.text, "still here");

    bob2.send_message(&alice_id, "yes still here")
        .await
        .expect("bob2 send");
    let env = rx_a2.recv().await.expect("alice2 envelope");
    let msg = alice2
        .handle_incoming(env)
        .await
        .expect("alice2 recv")
        .expect("text");
    assert_eq!(msg.text, "yes still here");

    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

/// 高频突发发送回归：一条条串行（发送队列），并发快速连发 N 条后，
/// 接收方必须全部收到且顺序不乱（此前并发加密读到相同未提交棘轮状态，
/// 多条消息 msg_id 相同，接收方去重丢弃后面几条）。
#[tokio::test]
async fn rapid_burst_all_delivered() {
    let dir_a = std::env::temp_dir().join(format!("privchat-rb-a-{}", std::process::id()));
    let dir_b = std::env::temp_dir().join(format!("privchat-rb-b-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);

    let (alice, _rx_a) = App::start_no_relay(dir_a.clone(), TEST_KEY)
        .await
        .expect("start a");
    let (bob, mut rx_b) = App::start_no_relay(dir_b.clone(), TEST_KEY)
        .await
        .expect("start b");

    let (alice_for_bob, alice_invite) = new_invite(&alice).await;
    let (bob_for_alice, bob_invite) = new_invite(&bob).await;
    let bob_id = alice.connect_peer(&bob_invite, None).await.expect("a->b");
    let alice_id = bob.connect_peer(&alice_invite, None).await.expect("b->a");

    // 并发快速连发 12 条（模拟前端高频发送）。
    let texts: Vec<String> = (0..12).map(|i| format!("burst {i}")).collect();
    let mut senders = Vec::new();
    for t in &texts {
        let a = alice.clone();
        let b = bob_id.clone();
        let t = t.clone();
        senders.push(tokio::spawn(async move {
            a.send_message(&b, &t).await.expect("burst send")
        }));
    }
    for s in senders {
        s.await.expect("burst task");
    }

    // 接收方必须收到全部 12 条且按 (gen, n) 顺序不乱。
    let mut received = Vec::new();
    for _ in 0..12 {
        let env = tokio::time::timeout(std::time::Duration::from_secs(20), rx_b.recv())
            .await
            .expect("bob envelope timeout")
            .expect("bob envelope");
        let msg = bob
            .handle_incoming(env)
            .await
            .expect("bob recv")
            .expect("text");
        received.push(msg.text);
    }
    assert_eq!(received, texts, "all burst messages must arrive in order");

    // 队列串行：每条 msg_id 唯一（gen/n 递增），无重复。
    let hist = bob.get_history(&alice_id).await;
    assert_eq!(hist.len(), 12, "history must have all 12");
    let mut ids = hist.iter().map(|m| m.id.clone()).collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 12, "all msg_ids must be unique");

    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

/// 单边邀请双向打通：只有 Alice 分享邀请（专属身份票据），Bob 连接
/// 即可发首条消息，Alice 自动登记 Bob 并回信。
#[tokio::test]
async fn single_invite_bidirectional() {
    let dir_a = std::env::temp_dir().join(format!("privchat-si-a-{}", std::process::id()));
    let dir_b = std::env::temp_dir().join(format!("privchat-si-b-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);

    let (alice, mut rx_a) = App::start_no_relay(dir_a.clone(), TEST_KEY)
        .await
        .expect("start a");
    let (bob, mut rx_b) = App::start_no_relay(dir_b.clone(), TEST_KEY)
        .await
        .expect("start b");

    // 只有 Alice 出邀请（专属身份）。测试因无 DNS 用完整票据。
    let (alice_for_bob, alice_invite) = new_invite(&alice).await;
    let alice_id = bob
        .connect_peer(&alice_invite, Some("Alice".into()))
        .await
        .expect("b->a");
    assert_eq!(alice_id, alice_for_bob);

    // Bob 首条消息。
    bob.send_message(&alice_id, "hi alice")
        .await
        .expect("bob send");
    let env = rx_a.recv().await.expect("alice envelope");
    let msg = alice
        .handle_incoming(env)
        .await
        .expect("alice recv")
        .expect("text");
    assert_eq!(msg.text, "hi alice");

    // Alice 自动建立了对 Bob 的联系人（无需 Bob 的邀请）。
    let alice_contacts = alice.list_contacts().await;
    assert!(
        alice_contacts.iter().any(|c| c.peer_id == msg.from),
        "alice should auto-register bob as a contact"
    );
    let bob_id = msg.from.clone();

    // Alice 回信。
    alice
        .send_message(&bob_id, "hi bob")
        .await
        .expect("alice reply");
    let env = rx_b.recv().await.expect("bob envelope");
    let msg = bob
        .handle_incoming(env)
        .await
        .expect("bob recv")
        .expect("text");
    assert_eq!(msg.text, "hi bob");
    assert_eq!(msg.from, alice_for_bob);

    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

/// 删除联系人：联系人表、专属身份与历史会话都被清理，重启后仍保持删除。
#[tokio::test]
async fn delete_contact_cleans_everything() {
    let dir_a = std::env::temp_dir().join(format!("privchat-del-a-{}", std::process::id()));
    let dir_b = std::env::temp_dir().join(format!("privchat-del-b-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);

    let (alice, _rx_a) = App::start_no_relay(dir_a.clone(), TEST_KEY)
        .await
        .expect("start a");
    let (bob, _rx_b) = App::start_no_relay(dir_b.clone(), TEST_KEY)
        .await
        .expect("start b");
    let (alice_for_bob, alice_invite) = new_invite(&alice).await;
    let (bob_for_alice, bob_invite) = new_invite(&bob).await;
    let bob_id = alice
        .connect_peer(&bob_invite, Some("Bob".into()))
        .await
        .expect("a->b");
    let _alice_id = bob.connect_peer(&alice_invite, None).await.expect("b->a");

    // 先发一条消息产生历史。
    alice
        .send_message(&bob_id, "before delete")
        .await
        .expect("send");
    assert!(!alice.get_history(&bob_id).await.is_empty());

    // 删除后：联系人、历史全部消失。
    alice.delete_contact(&bob_id).await.expect("delete");
    assert!(alice.list_contacts().await.is_empty());
    assert!(alice.get_history(&bob_id).await.is_empty());

    // 重启后仍然保持删除（持久化生效）。
    alice.close().await;
    drop(alice);
    let (alice2, _rx_a2) = App::start_no_relay(dir_a.clone(), TEST_KEY)
        .await
        .expect("restart a");
    assert!(alice2.list_contacts().await.is_empty());
    assert!(alice2.get_history(&bob_id).await.is_empty());

    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

/// 防冲突：同一专属身份（local_id）只允许绑定一个联系人；同一联系
/// 只允许绑定一个专属身份。伪造信（身份已被别的 peer 占用 / peer
/// 已绑到别的身份）必须被拒绝，且不污染联系人表。
#[tokio::test]
async fn handle_incoming_rejects_identity_conflicts() {
    let dir_a = std::env::temp_dir().join(format!("privchat-cf-a-{}", std::process::id()));
    let dir_b = std::env::temp_dir().join(format!("privchat-cf-b-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);

    let (alice, _rx_a) = App::start_no_relay(dir_a.clone(), TEST_KEY)
        .await
        .expect("start a");
    let (bob, _rx_b) = App::start_no_relay(dir_b.clone(), TEST_KEY)
        .await
        .expect("start b");

    // Alice 与 Bob 双向建立：Alice 对 Bob 生成专属身份 alice_for_bob。
    let (alice_for_bob, alice_invite) = new_invite(&alice).await;
    let (bob_for_alice, bob_invite) = new_invite(&bob).await;
    let bob_id = alice
        .connect_peer(&bob_invite, Some("Bob".into()))
        .await
        .expect("a->b");
    let _alice_id = bob.connect_peer(&alice_invite, None).await.expect("b->a");

    let alice_contacts = alice.list_contacts().await;
    let alice_local_for_bob = alice_contacts
        .iter()
        .find(|c| c.peer_id == bob_id)
        .expect("bob contact")
        .local_id
        .clone();

    // 伪造信 1：本地身份 alice_local_for_bob 已被 Bob 占用，却声称来自
    // Mallory（一个合法格式、但与 Bob 不同的 peer_id）—— 必须被拒绝。
    let mallory = iroh::SecretKey::generate();
    let mallory_id = mallory.public().to_string();
    let forge1 = IncomingEnvelope {
        local_id: alice_local_for_bob.clone(),
        peer_id: mallory_id,
        payload: serde_json::to_vec(&WireMessage {
            msg_id: test_msg_id(),
            to_peer_id: alice_for_bob.clone(),
            msg: vec![0u8; 13],
        })
        .unwrap(),
    };
    assert!(
        alice
            .handle_incoming(forge1)
            .await
            .expect("reject")
            .is_none(),
        "identity already bound to bob must reject mallory"
    );

    // 伪造信 2：Bob 本人已绑 alice_local_for_bob，却声称通过另一身份
    // （从未生成过的）到达 —— 必须被拒绝。
    let forged_local = iroh::SecretKey::generate().public().to_string();
    let forge2 = IncomingEnvelope {
        local_id: forged_local,
        peer_id: bob_id.clone(),
        payload: serde_json::to_vec(&WireMessage {
            msg_id: test_msg_id(),
            to_peer_id: alice_for_bob.clone(),
            msg: vec![0u8; 13],
        })
        .unwrap(),
    };
    assert!(
        alice
            .handle_incoming(forge2)
            .await
            .expect("reject")
            .is_none(),
        "peer already bound to other identity must reject"
    );

    // 两条伪造消息都不应新增联系人，也不应改绑 Bob 的绑定身份。
    let contacts = alice.list_contacts().await;
    assert_eq!(contacts.len(), 1, "no new contact from forged messages");
    assert_eq!(contacts[0].local_id, alice_local_for_bob);

    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

/// 生产模式（relay 开启）下两个客户端的真实互通路径。两进程在同一台机器，
/// 直连 + relay 都应可达，且用纯 peer_id（生产邀请格式）连接。
#[tokio::test]
#[ignore = "需要访问公网 relay + DNS，联机时手动运行"]
async fn two_clients_roundtrip_with_relay() {
    let dir_a = std::env::temp_dir().join(format!("privchat-rl-a-{}", std::process::id()));
    let dir_b = std::env::temp_dir().join(format!("privchat-rl-b-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);

    let (alice, mut rx_a) = App::start(dir_a.clone(), TEST_KEY).await.expect("start a");
    let (bob, mut rx_b) = App::start(dir_b.clone(), TEST_KEY).await.expect("start b");

    // 生产邀请 = 专属身份的 peer_id（几十字符，可进二维码），靠 DNS/Pkarr 解析地址。
    let (alice_for_bob, alice_invite) = new_invite(&alice).await;
    let (bob_for_alice, bob_invite) = new_invite(&bob).await;

    let bob_id = alice
        .connect_peer(&bob_invite, Some("Bob".into()))
        .await
        .expect("a->b");
    let alice_id = bob.connect_peer(&alice_invite, None).await.expect("b->a");
    assert_eq!(bob_id, bob_for_alice);
    assert_eq!(alice_id, alice_for_bob);

    alice
        .send_message(&bob_id, "hello bob via relay")
        .await
        .expect("alice send");
    let env = rx_b.recv().await.expect("bob envelope");
    let msg = bob
        .handle_incoming(env)
        .await
        .expect("bob recv")
        .expect("text");
    assert_eq!(msg.text, "hello bob via relay");

    bob.send_message(&alice_id, "hi alice via relay")
        .await
        .expect("bob send");
    let env = rx_a.recv().await.expect("alice envelope");
    let msg = alice
        .handle_incoming(env)
        .await
        .expect("alice recv")
        .expect("text");
    assert_eq!(msg.text, "hi alice via relay");

    alice.close().await;
    bob.close().await;
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

/// 真实链路端到端验证：client0 专属身份加密消息 -> PUT mailbox0 -> 网格
/// 同步 -> mailbox1 -> client1 专属身份经 mailbox1 fetch 解密。
///
/// 前置条件（本机集成用）：
/// - 环境变量 `PRIVCHAT_TEST_MB0` / `PRIVCHAT_TEST_MB1` 指定运行中的
///   mailbox 节点 peer_id；
/// - `PRIVCHAT_TEST_KEY_A` / `PRIVCHAT_TEST_KEY_B` 指向双方真实长期身份
///   （缺省回退到 `D:\PrivChat\client0|client1\secret.key`）；
/// - 需联网（relay/DNS）。
#[tokio::test]
#[ignore = "需要运行中的 mailbox 节点 + 联网 + 真实身份密钥"]
async fn mailbox_grid_sync_end_to_end() {
    let mb0 = std::env::var("PRIVCHAT_TEST_MB0").expect("PRIVCHAT_TEST_MB0");
    let mb1 = std::env::var("PRIVCHAT_TEST_MB1").expect("PRIVCHAT_TEST_MB1");
    let key_a = std::env::var("PRIVCHAT_TEST_KEY_A")
        .unwrap_or_else(|_| "D:\\PrivChat\\client0\\secret.key".into());
    let key_b = std::env::var("PRIVCHAT_TEST_KEY_B")
        .unwrap_or_else(|_| "D:\\PrivChat\\client1\\secret.key".into());

    let dir_a = std::env::temp_dir().join(format!("privchat-mb-a-{}", std::process::id()));
    let dir_b = std::env::temp_dir().join(format!("privchat-mb-b-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::create_dir_all(&dir_b).unwrap();
    std::fs::copy(&key_a, dir_a.join("secret.key")).unwrap();
    std::fs::copy(&key_b, dir_b.join("secret.key")).unwrap();

    let alice_key = read_secret_key(&dir_a.join("secret.key"));
    let bob_key = read_secret_key(&dir_b.join("secret.key"));
    let alice_id = alice_key.public().to_string();
    let bob_id = bob_key.public().to_string();

    let utc_time = now_ms();
    let plain = PlainMsg {
        msg_text: "grid hello from client0".to_string(),
        utc_time,
    };
    let spk_sk = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let spk_pk = x25519_dalek::PublicKey::from(&spk_sk).to_bytes();
    let mut ratchet_a =
        crypto::Ratchet::new_initiator(&alice_key, &bob_id, &spk_pk, None).expect("ratchet a");
    let mut ratchet_b =
        crypto::Ratchet::new_responder(&bob_key, &alice_id, &spk_sk.to_bytes(), None)
            .expect("ratchet b");
    let blob = ratchet_a
        .encrypt(&serde_json::to_vec(&plain).unwrap())
        .expect("encrypt");
    // 与生产一致：msg_id 由 (gen, n) + 发送方身份派生，不含时间戳。
    let msg_id = msg_id_for(&alice_id, &blob);

    // client0 身份：PUT 到 mailbox0。
    let alice_mb = MailboxClient::start(dir_a.clone())
        .await
        .expect("alice mailbox");
    MailboxClient::put(&alice_mb, &mb0, &bob_id, &msg_id, blob.clone())
        .await
        .expect("put to mailbox0");

    // 等待网格同步 -> mailbox1。
    tokio::time::sleep(std::time::Duration::from_secs(6)).await;

    // client1 身份：从 mailbox1 fetch 并解密（节点侧取回即删，并广播删除同步）。
    let bob_mb = MailboxClient::start(dir_b.clone())
        .await
        .expect("bob mailbox");
    let fetched = MailboxClient::fetch(&bob_mb, &mb1, &bob_id)
        .await
        .expect("fetch from mailbox1");
    let stored = fetched
        .iter()
        .find(|m| m.msg_id == msg_id)
        .expect("message synced to mailbox1");
    let plain2 = ratchet_b.decrypt(&stored.msg).expect("decrypt");
    let got: PlainMsg = serde_json::from_slice(&plain2).unwrap();
    assert_eq!(got.msg_text, "grid hello from client0");

    // 清理验证：fetch 取回即删 + 网格反向同步，mailbox0 的副本也应被删除。
    // 队列归属认证：只能用 Bob 自己的身份（bob_mb）检查 Bob 的队列。
    tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    let after = MailboxClient::fetch(&bob_mb, &mb0, &bob_id)
        .await
        .expect("recheck mailbox0");
    assert!(
        !after.iter().any(|m| m.msg_id == msg_id),
        "fetch-delete should remove from mailbox0 via grid"
    );

    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

fn read_secret_key(path: &std::path::Path) -> iroh::SecretKey {
    let bytes = std::fs::read(path).expect("secret.key");
    iroh::SecretKey::try_from(bytes.as_slice()).expect("valid key")
}

/// msg_id 确定性：同一 (local_id, 密文) 必然生成相同 ID（重试去重的前提），
/// 且不同方向（不同 local_id）即使 (gen, n) 相同也不会撞车（此前随机尾
/// 修复的回归点：双方各从 gen0/n0 开始，方向必须靠身份后缀区分）。
#[test]
fn msg_id_is_deterministic_and_direction_unique() {
    let alice = iroh::SecretKey::generate();
    let bob = iroh::SecretKey::generate();
    let bob_id = bob.public().to_string();
    let alice_id = alice.public().to_string();

    let plain = serde_json::to_vec(&PlainMsg {
        msg_text: "same text".into(),
        utc_time: 1,
    })
    .unwrap();
    let alice_spk = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let alice_spk_pk = x25519_dalek::PublicKey::from(&alice_spk).to_bytes();
    let mut a = crypto::Ratchet::new_initiator(&alice, &bob_id, &alice_spk_pk, None).unwrap();
    // 双方各自作为发起方（并发发起在会话层合并，这里只验证 msg_id 方向不撞）。
    let mut b = crypto::Ratchet::new_initiator(&bob, &alice_id, &alice_spk_pk, None).unwrap();
    let blob_a = a.encrypt(&plain).unwrap();
    let blob_b = b.encrypt(&plain).unwrap();

    // 双方首条消息 (gen0, n0) 相同，但方向后缀不同 -> ID 不同。
    let id_a1 = msg_id_for(&alice_id, &blob_a);
    let id_b1 = msg_id_for(&bob_id, &blob_b);
    assert_ne!(id_a1, id_b1, "cross-direction collision");

    // 同方向同密文重加密（ack 丢失重试）：密文可能因时间刷新变化，
    // 但若 (gen, n) 相同，ID 前缀一致 —— 这里直接验证同一密文的确定性。
    let id_a2 = msg_id_for(&alice_id, &blob_a);
    assert_eq!(id_a1, id_a2, "msg_id must be deterministic");

    // 前缀即 (gen, n)，字典序等于棘轮序。
    a.next();
    let blob_a1 = a.encrypt(&plain).unwrap();
    assert!(msg_id_for(&alice_id, &blob_a) < msg_id_for(&alice_id, &blob_a1));
}

/// 测试用唯一 ID（无需 (gen,n) 前缀）。
fn test_msg_id() -> String {
    use rand_core::RngCore;
    let mut rnd = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut rnd);
    rnd.iter().map(|b| format!("{b:02x}")).collect()
}

/// 并发发起：双方都还没收到对方就先各发一条，会各产生两段会话。
/// 主会话按 session_id 取小，两边选出的必须是同一段；两条消息都不能丢。
#[tokio::test]
async fn concurrent_first_send_converges_on_one_active_session() {
    let dir_a = std::env::temp_dir().join(format!("privchat-cc-a-{}", std::process::id()));
    let dir_b = std::env::temp_dir().join(format!("privchat-cc-b-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);

    let (alice, mut rx_a) = App::start_no_relay(dir_a.clone(), TEST_KEY)
        .await
        .expect("start a");
    let (bob, mut rx_b) = App::start_no_relay(dir_b.clone(), TEST_KEY)
        .await
        .expect("start b");

    let (alice_for_bob, alice_invite) = new_invite(&alice).await;
    let (bob_for_alice, bob_invite) = new_invite(&bob).await;
    let bob_id = alice.connect_peer(&bob_invite, None).await.expect("a->b");
    let alice_id = bob.connect_peer(&alice_invite, None).await.expect("b->a");

    // 谁都没收过对方：两边同时发，各自成为发起方。
    alice
        .send_message(&bob_id, "a-first")
        .await
        .expect("a send");
    bob.send_message(&alice_id, "b-first")
        .await
        .expect("b send");
    let env_b = rx_b.recv().await.expect("bob envelope");
    let env_a = rx_a.recv().await.expect("alice envelope");

    let msg_b = bob
        .handle_incoming(env_b)
        .await
        .expect("bob recv")
        .expect("text");
    assert_eq!(msg_b.text, "a-first");
    let msg_a = alice
        .handle_incoming(env_a)
        .await
        .expect("alice recv")
        .expect("text");
    assert_eq!(msg_a.text, "b-first");

    // 两边都应有两条会话，且选出的主会话 ID 一致。
    let key_a = (alice_for_bob.clone(), bob_id.clone());
    let key_b = (bob_for_alice.clone(), alice_id.clone());
    let (active_a, count_a) = {
        let map = alice.sessions.lock().await;
        let entries = map.get(&key_a).expect("alice sessions");
        (
            entries.iter().find(|e| e.active).map(|e| e.id.clone()),
            entries.len(),
        )
    };
    let (active_b, count_b) = {
        let map = bob.sessions.lock().await;
        let entries = map.get(&key_b).expect("bob sessions");
        (
            entries.iter().find(|e| e.active).map(|e| e.id.clone()),
            entries.len(),
        )
    };
    assert_eq!(count_a, 2, "alice should keep both concurrent sessions");
    assert_eq!(count_b, 2, "bob should keep both concurrent sessions");
    assert_eq!(active_a, active_b, "both sides must elect the same session");

    // 继续双向通信：主会话一致，消息不丢。
    alice.send_message(&bob_id, "a2").await.expect("a send 2");
    let env = rx_b.recv().await.expect("bob envelope 2");
    let m = bob
        .handle_incoming(env)
        .await
        .expect("bob recv 2")
        .expect("text");
    assert_eq!(m.text, "a2");

    bob.send_message(&alice_id, "b2").await.expect("b send 2");
    let env = rx_a.recv().await.expect("alice envelope 2");
    let m = alice
        .handle_incoming(env)
        .await
        .expect("alice recv 2")
        .expect("text");
    assert_eq!(m.text, "b2");

    alice.close().await;
    bob.close().await;
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

/// OPK 一次性：发起方用掉一把、响应方解出后删掉一把。
#[tokio::test]
async fn session_consumes_one_time_prekey() {
    let dir_a = std::env::temp_dir().join(format!("privchat-opk-a-{}", std::process::id()));
    let dir_b = std::env::temp_dir().join(format!("privchat-opk-b-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);

    let (alice, _rx_a) = App::start_no_relay(dir_a.clone(), TEST_KEY)
        .await
        .expect("start a");
    let (bob, mut rx_b) = App::start_no_relay(dir_b.clone(), TEST_KEY)
        .await
        .expect("start b");
    let (alice_for_bob, alice_invite) = new_invite(&alice).await;
    let (bob_for_alice, bob_invite) = new_invite(&bob).await;
    let bob_id = alice.connect_peer(&bob_invite, None).await.expect("a->b");
    let _ = bob.connect_peer(&alice_invite, None).await.expect("b->a");

    // 邀请里带了 4 把 OPK，发起会话会先用掉一把。
    let before = alice
        .contacts
        .lock()
        .await
        .get(&bob_id)
        .map(|c| c.peer_opks.len())
        .unwrap_or(0);
    assert_eq!(before, 4, "invite should carry 4 OPKs");

    let bob_local = bob_for_alice.clone();
    let bob_opks_before = bob.store.count_unused_opks(&bob_local).expect("count");

    alice
        .send_message(&bob_id, "opk hello")
        .await
        .expect("send");
    let env = rx_b.recv().await.expect("bob envelope");
    let msg = bob.handle_incoming(env).await.expect("recv").expect("text");
    assert_eq!(msg.text, "opk hello");

    let after = alice
        .contacts
        .lock()
        .await
        .get(&bob_id)
        .map(|c| c.peer_opks.len())
        .unwrap_or(0);
    assert_eq!(after, 3, "initiator should consume one peer OPK");

    let bob_opks_after = bob.store.count_unused_opks(&bob_local).expect("count");
    assert_eq!(
        bob_opks_before - 1,
        bob_opks_after,
        "responder should delete the used OPK"
    );

    alice.close().await;
    bob.close().await;
    let _ = alice_for_bob;
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}
