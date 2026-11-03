const A = "a".repeat(64);
const B = "b".repeat(64);
const contacts = [
  { peer_id: A, name: "小鲸鱼", local_id: "l1" },
  { peer_id: B, name: "测试联系人", local_id: "l2" },
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
    case "list_contacts":
      return contacts;
    case "get_history":
      return history[args.peerId] || [];
    case "get_mailbox_peers":
      return [B];
    case "get_mailbox_write_count":
      return 3;
    case "get_onion_config":
      return { enabled: true, relays: [B, A] };
    case "get_auto_lock_minutes":
      return 5;
    case "get_self_ticket":
      return A;
    default:
      return null;
  }
}
