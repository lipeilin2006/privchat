const A = "a".repeat(64);
const B = "b".repeat(64);

// 新协议：没有联系人实体，只有连接（conn_id + 备注）。
const connections = [
  { conn_id: A, name: "小鲸鱼", state: "established" },
  { conn_id: B, name: "测试连接", state: "established" },
];

const history = {
  [A]: [
    { id: "1", from: "peer", text: "姐姐在干嘛呀～", time: Date.now() - 600000, status: "received" },
    { id: "2", from: "me", text: "在改界面呢", time: Date.now() - 500000, status: "sent" },
    { id: "3", from: "peer", text: "那鱼鱼等姐姐改完～", time: Date.now() - 400000, status: "received" },
  ],
  [B]: [{ id: "4", from: "peer", text: "测试消息", time: Date.now() - 86400000 }],
};

export async function invoke(cmd, args) {
  switch (cmd) {
    case "vault_status":
      return {
        initialized: true,
        unlocked: !new URLSearchParams(window.location.search).has("locked"),
      };
    case "list_connections":
      return connections;
    case "connection_history":
      return history[args.connId] || [];
    case "poll_connection":
      return [];
    case "create_connection":
      return [A, "px1:mockinvite"];
    case "accept_connection":
    case "send_on_connection":
    case "rename_connection":
      return null;
    case "get_mailbox_peers":
      return [{ peer_id: B, priority: 3 }];
    case "add_mailbox_peer":
    case "remove_mailbox_peer":
    case "set_mailbox_priority":
    case "set_mailbox_weight":
    case "set_onion_config":
      return null;
    case "ping_mailbox":
      return 42;
    case "ping_mailboxes":
      return [{ peer_id: B, ms: 42, error: null }];
    case "mailbox_latency":
      return { [B]: 42 };
    case "get_mailbox_weight":
      return 0.5;
    case "get_onion_config":
      return {
        enabled: true,
        mode: "static",
        relays: [
          { peer_id: B, priority: 0 },
          { peer_id: A, priority: 0 },
        ],
        hops: 2,
        weight: 0.5,
      };
    case "test_onion_relays":
      return [{ peer_id: B, ms: 55, error: null }];
    case "onion_relay_latency":
      return { [B]: 55 };
    case "export_diagnostics":
      return { app_version: "0.1.0", mailbox_count: 1 };
    case "get_auto_lock_minutes":
      return 5;
    default:
      return null;
  }
}
