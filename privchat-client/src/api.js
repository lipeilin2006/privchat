import { invoke } from "@tauri-apps/api/core";

export const api = {
  vaultStatus: () => invoke("vault_status"),
  createVault: (password) => invoke("create_vault", { password }),
  unlockVault: (password) => invoke("unlock_vault", { password }),
  lockVault: () => invoke("lock_vault"),
  changePassword: (oldPassword, newPassword) =>
    invoke("change_vault_password", { oldPassword, newPassword }),


  // 新协议：连接（没有「联系人」实体，只有连接 + 备注）
  createConnection: (mailbox = null) => invoke("create_connection", { mailbox }),
  acceptConnection: (connId, invite) =>
    invoke("accept_connection", { connId, invite }),
  deleteConnection: (connId) => invoke("delete_connection", { connId }),
  rotateConnection: (connId) => invoke("rotate_connection", { connId }),
  sendOnConnection: (connId, text) =>
    invoke("send_on_connection", { connId, text }),
  searchMessages: (query, limit = 30) => invoke("search_messages", { query, limit }),
  attachmentData: (connId, msgId) => invoke("attachment_data", { connId, msgId }),
  exportAttachment: (connId, msgId) => invoke("export_attachment", { connId, msgId }),
  sendFile: (connId, name, mime, data) =>
    invoke("send_file", { connId, name, mime, data }),
  listConnections: () => invoke("list_connections"),
  connectionHistory: (connId) => invoke("connection_history", { connId }),
  renameConnection: (connId, name) =>
    invoke("rename_connection", { connId, name }),

  mailboxPeers: () => invoke("get_mailbox_peers"),
  addMailbox: (peerId, priority = 0) => invoke("add_mailbox_peer", { peerId, priority }),
  removeMailbox: (peerId) => invoke("remove_mailbox_peer", { peerId }),
  setMailboxPriority: (peerId, priority) =>
    invoke("set_mailbox_priority", { peerId, priority }),
  pingMailbox: (peerId) => invoke("ping_mailbox", { peerId }),
  pingMailboxes: () => invoke("ping_mailboxes"),
  mailboxLatency: () => invoke("mailbox_latency"),
  getMailboxWeight: () => invoke("get_mailbox_weight"),
  setMailboxWeight: (weight) => invoke("set_mailbox_weight", { weight }),

  getOnion: () => invoke("get_onion_config"),
  setOnion: (config) => invoke("set_onion_config", { config }),
  testOnionRelays: () => invoke("test_onion_relays"),
  onionRelayLatency: () => invoke("onion_relay_latency"),

  autoLock: () => invoke("get_auto_lock_minutes"),
  setAutoLock: (minutes) => invoke("set_auto_lock_minutes", { minutes }),
  diagnostics: () => invoke("export_diagnostics"),
  exitApp: () => invoke("exit_app"),
};
