//! PrivChat Mailbox 共享库：协议类型 + 客户端/节点间发送原语。
//!
//! 协议本体统一放在 `privchat-common`（见 [`privchat_common`]），本 crate
//! 只是转发，供 `main.rs`（节点本体）与 `examples/client.rs`（命令行测试
//! 客户端）按原有路径 `privchat_mailbox::*` 引用。

pub mod node;
pub mod store;

pub use privchat_common::{
    make_endpoint, send_request, MailboxRequest, MailboxResponse, Op, StoredMessage, ALPN,
    MAX_PAYLOAD,
};
