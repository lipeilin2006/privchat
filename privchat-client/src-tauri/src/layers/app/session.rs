//! 会话模型：角色、会话条目与主会话选举。

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;

use super::crypto;

/// 会话角色：第一个发消息的一方是发起方，另一方是响应方。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum SessionRole {
    Initiator,
    Responder,
}

impl SessionRole {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            SessionRole::Initiator => "initiator",
            SessionRole::Responder => "responder",
        }
    }
    pub(super) fn from_str(s: &str) -> Option<Self> {
        match s {
            "initiator" => Some(SessionRole::Initiator),
            "responder" => Some(SessionRole::Responder),
            _ => None,
        }
    }
}

/// 一条会话：session_id + 角色 + 棘轮状态。
/// 一个联系人可以同时存在多条（并发发起时），按 session_id 字典序取最小者为主。
#[derive(Clone)]
pub(super) struct SessionEntry {
    pub(super) id: String,
    pub(super) role: SessionRole,
    pub(super) ratchet: crypto::Ratchet,
    pub(super) active: bool,
}

pub(super) type SessionMap = Arc<Mutex<HashMap<(String, String), Vec<SessionEntry>>>>;

/// 主会话选举：按 session_id 排序后取最小者。
///
/// 并发发起时双方各有一段会话，但两边看到的 ID 集合相同（ID 由双方 IK 与
/// 发起方 EK 算出），所以选出的主会话也一致，不会来回抖。
pub(super) fn session_rows(entries: &[SessionEntry]) -> Vec<(String, String, bool, Vec<u8>)> {
    entries
        .iter()
        .map(|e| {
            (
                e.id.clone(),
                e.role.as_str().to_string(),
                e.active,
                e.ratchet.to_bytes(),
            )
        })
        .collect()
}

pub(super) fn elect_active(entries: &mut Vec<SessionEntry>) {
    entries.sort_by(|a, b| a.id.cmp(&b.id));
    for (i, e) in entries.iter_mut().enumerate() {
        e.active = i == 0;
    }
}
