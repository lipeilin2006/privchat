//! 连接协议 × 真实 mailbox 节点（本地回环、无 relay）。

use std::sync::Arc;

use iroh_tickets::endpoint::EndpointTicket;
use iroh_tickets::Ticket;
use privchat_client_lib::layers::app::OnionConfig;
use privchat_client_lib::layers::links::{IrohQueues, LinkManager, ReceivedFrame};
use privchat_client_lib::layers::store::Store;
use privchat_client_lib::layers::transport::Transport;

const KEY: [u8; 32] = [9u8; 32];

fn texts(frames: Vec<ReceivedFrame>) -> Vec<String> {
    frames
        .into_iter()
        .filter_map(|frame| match frame {
            ReceivedFrame::Text(text) => Some(text),
            _ => None,
        })
        .collect()
}

async fn manager(dir: &str, transport: Transport) -> (LinkManager, Arc<Store>) {
    let path =
        std::env::temp_dir().join(format!("privchat-mailbox-it-{dir}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    let store = Arc::new(Store::open(&path, KEY).expect("store"));
    let onion = Arc::new(tokio::sync::Mutex::new(OnionConfig::default()));
    let api = Arc::new(IrohQueues::new(
        transport,
        onion,
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
    ));
    let links = LinkManager::load(store.clone(), api).await.expect("load");
    (links, store)
}

#[tokio::test]
async fn two_clients_over_real_mailbox() {
    let node_dir = std::env::temp_dir().join(format!("privchat-node-{}", std::process::id()));
    let node = privchat_mailbox::node::spawn_test_node(&node_dir, 0)
        .await
        .expect("spawn node");
    let mailbox = EndpointTicket::new(node.endpoint.addr()).encode_string();

    // 两个客户端各自一套存储 + 传输（无 relay）。
    let dir_a = std::env::temp_dir().join(format!("privchat-mb-a-{}", std::process::id()));
    let dir_b = std::env::temp_dir().join(format!("privchat-mb-b-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::create_dir_all(&dir_b).unwrap();
    let store_a = Arc::new(Store::open(&dir_a, KEY).expect("store a"));
    let store_b = Arc::new(Store::open(&dir_b, KEY).expect("store b"));
    let transport_a = Transport::start_no_relay(store_a.clone())
        .await
        .expect("transport a");
    let transport_b = Transport::start_no_relay(store_b.clone())
        .await
        .expect("transport b");

    let (a, _sa) = manager("a", transport_a).await;
    let (b, _sb) = manager("b", transport_b).await;

    // 各自建队列、出邀请；互扫配对。
    let (a_id, a_invite) = a.create(&mailbox).await.expect("a create");
    let (b_id, b_invite) = b.create(&mailbox).await.expect("b create");
    a.accept(&a_id, &b_invite).await.expect("a accept");
    b.accept(&b_id, &a_invite).await.expect("b accept");

    // A → B（走真实 mailbox 节点）。
    a.send(&a_id, b"hello over mailbox").await.expect("a send");
    let got = b.poll(&b_id).await.expect("b poll");
    assert_eq!(texts(got), vec!["hello over mailbox".to_string()]);

    // B → A。
    b.send(&b_id, b"hi back").await.expect("b send");
    let got = a.poll(&a_id).await.expect("a poll");
    assert_eq!(texts(got), vec!["hi back".to_string()]);

    // 取回即删。
    assert!(b.poll(&b_id).await.unwrap().is_empty());

    node.shutdown().await;
}

/// 图片/附件走真实 mailbox：分片 → 取回 → 拼装，字节要一致。
#[tokio::test]
async fn image_over_real_mailbox() {
    let node_dir = std::env::temp_dir().join(format!("privchat-node-file-{}", std::process::id()));
    let node = privchat_mailbox::node::spawn_test_node(&node_dir, 0)
        .await
        .expect("spawn node");
    let mailbox = EndpointTicket::new(node.endpoint.addr()).encode_string();

    let dir_a = std::env::temp_dir().join(format!("privchat-file-a-{}", std::process::id()));
    let dir_b = std::env::temp_dir().join(format!("privchat-file-b-{}", std::process::id()));
    for dir in [&dir_a, &dir_b] {
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).unwrap();
    }
    let store_a = Arc::new(Store::open(&dir_a, KEY).expect("store a"));
    let store_b = Arc::new(Store::open(&dir_b, KEY).expect("store b"));
    let transport_a = Transport::start_no_relay(store_a.clone()).await.unwrap();
    let transport_b = Transport::start_no_relay(store_b.clone()).await.unwrap();
    let (a, _) = manager("file-a", transport_a).await;
    let (b, _) = manager("file-b", transport_b).await;

    let (a_id, a_invite) = a.create(&mailbox).await.expect("a create");
    let (b_id, b_invite) = b.create(&mailbox).await.expect("b create");
    a.accept(&a_id, &b_invite).await.expect("a accept");
    b.accept(&b_id, &a_invite).await.expect("b accept");

    // 200KB 假图片：足以跨多个 24KB 分片
    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    a.send_file(&a_id, "pic.png", "image/png", &payload)
        .await
        .expect("send file");

    let frames = b.poll(&b_id).await.expect("b poll");
    let file = frames.into_iter().find_map(|frame| match frame {
        ReceivedFrame::File { name, mime, data } => Some((name, mime, data)),
        _ => None,
    });
    let (name, mime, data) = file.expect("file frame");
    assert_eq!(name, "pic.png");
    assert_eq!(mime, "image/png");
    assert_eq!(data.len(), payload.len());
    assert_eq!(data, payload, "image bytes must survive the roundtrip");

    node.shutdown().await;
}
