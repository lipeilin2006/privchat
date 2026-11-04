import { invoke } from "@tauri-apps/api/core";

export const api = {
  vaultStatus: () => invoke("vault_status"),
  createVault: (password) => invoke("create_vault", { password }),
  unlockVault: (password) => invoke("unlock_vault", { password }),
  lockVault: () => invoke("lock_vault"),
  changePassword: (oldPassword, newPassword) =>
    invoke("change_vault_password", { oldPassword, newPassword }),

  listContacts: () => invoke("list_contacts"),
  getHistory: (peerId) => invoke("get_history", { peerId }),
  sendMessage: (peerId, text) => invoke("send_message", { peerId, text }),
  connectPeer: (invite, name) => invoke("connect_peer", { invite, name }),
  deleteContact: (peerId) => invoke("delete_contact", { peerId }),
  renameContact: (peerId, name) => invoke("rename_contact", { peerId, name }),
  selfTicket: () => invoke("get_self_ticket"),

  // 新协议：连接（没有「联系人」实体，只有连接 + 备注）
  createConnection: (mailbox) => invoke("create_connection", { mailbox }),
  acceptConnection: (connId, invite) =>
    invoke("accept_connection", { connId, invite }),
  sendOnConnection: (connId, text) =>
    invoke("send_on_connection", { connId, text }),
  pollConnection: (connId) => invoke("poll_connection", { connId }),
  listConnections: () => invoke("list_connections"),
  connectionHistory: (connId) => invoke("connection_history", { connId }),
  renameConnection: (connId, name) =>
    invoke("rename_connection", { connId, name }),

  mailboxPeers: () => invoke("get_mailbox_peers"),
  addMailbox: (peerId) => invoke("add_mailbox_peer", { peerId }),
  removeMailbox: (peerId) => invoke("remove_mailbox_peer", { peerId }),
  pingMailbox: (peerId) => invoke("ping_mailbox", { peerId }),
  getWriteCount: () => invoke("get_mailbox_write_count"),
  setWriteCount: (count) => invoke("set_mailbox_write_count", { count }),

  getOnion: () => invoke("get_onion_config"),
  setOnion: (config) => invoke("set_onion_config", { config }),

  autoLock: () => invoke("get_auto_lock_minutes"),
  setAutoLock: (minutes) => invoke("set_auto_lock_minutes", { minutes }),
  diagnostics: () => invoke("export_diagnostics"),
  exitApp: () => invoke("exit_app"),
};
