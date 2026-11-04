//! 连接协议 × 真实 mailbox 节点（本地回环、无 relay）。

use std::sync::Arc;

use iroh_tickets::endpoint::EndpointTicket;
use iroh_tickets::Ticket;
use privchat_client_lib::layers::links::{IrohQueues, LinkManager};
use privchat_client_lib::layers::store::Store;
use privchat_client_lib::layers::transport::Transport;

const KEY: [u8; 32] = [9u8; 32];

async fn manager(dir: &str, transport: Transport) -> (LinkManager, Arc<Store>) {
    let path =
        std::env::temp_dir().join(format!("privchat-mailbox-it-{dir}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    let store = Arc::new(Store::open(&path, KEY).expect("store"));
    let api = Arc::new(IrohQueues::new(transport));
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
    let (transport_a, _rx_a) = Transport::start_no_relay(store_a.clone())
        .await
        .expect("transport a");
    let (transport_b, _rx_b) = Transport::start_no_relay(store_b.clone())
        .await
        .expect("transport b");

    let (a, _sa) = manager("a", transport_a).await;
    let (b, _sb) = manager("b", transport_b).await;

    // 各自建队列、出邀请；互扫配对。
    let (a_id, a_invite) = a.create(&[mailbox.clone()]).await.expect("a create");
    let (b_id, b_invite) = b.create(&[mailbox.clone()]).await.expect("b create");
    a.accept(&a_id, &b_invite).await.expect("a accept");
    b.accept(&b_id, &a_invite).await.expect("b accept");

    // A → B（走真实 mailbox 节点）。
    a.send(&a_id, b"hello over mailbox").await.expect("a send");
    let got = b.poll(&b_id).await.expect("b poll");
    assert_eq!(got, vec![b"hello over mailbox".to_vec()]);

    // B → A。
    b.send(&b_id, b"hi back").await.expect("b send");
    let got = a.poll(&a_id).await.expect("a poll");
    assert_eq!(got, vec![b"hi back".to_vec()]);

    // 取回即删。
    assert!(b.poll(&b_id).await.unwrap().is_empty());

    node.shutdown().await;
}
