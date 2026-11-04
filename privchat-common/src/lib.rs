//! PrivChat 共享协议层：mailbox 客户端与信箱节点之间的 wire 协议。
//!
//! 客户端（`privchat-client`）与节点（`privchat-mailbox`）各自依赖本 crate，
//! 保证请求/响应结构与常量只维护一份，避免两处复制导致漂移。
//!
//! 协议：每条 QUIC bi-stream 一次请求。客户端写入 JSON 的
//! [`MailboxRequest`]，节点写回 JSON 的 [`MailboxResponse`]。
//! 操作码见 [`Op`]：`ping` 健康检查，其余四个是单向队列的
//! 建/写/取/删。节点之间没有同步协议。

use anyhow::{anyhow, Result};
use iroh::endpoint::presets;
use iroh::Endpoint;
use serde::{Deserialize, Serialize};

/// mailbox 节点唯一 ALPN：与客户端聊天 ALPN 区分。
pub const ALPN: &[u8] = b"privchat/mailbox";

/// 单条邮件容量上限（密文，含 overhead）。
pub const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

/// 十六进制编码（小写）。
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// 十六进制解码；长度奇数或含非法字符时报错。
pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(anyhow!("odd hex length"));
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks(2) {
        let hi = hex_val(pair[0]).ok_or_else(|| anyhow!("bad hex digit"))?;
        let lo = hex_val(pair[1]).ok_or_else(|| anyhow!("bad hex digit"))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// 请求方 → 节点请求。
///
/// 只带当前 op 需要的字段；其余留 `None`，serde 不序列化。
/// `Default` 给的是 Ping 的空请求。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxRequest {
    #[serde(rename = "op")]
    pub op: Op,
    /// 队列 id（16 字节，hex）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue: Option<String>,
    /// 队列创建时登记的 sender / owner 公钥（hex）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_auth: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_auth: Option<String>,
    /// 队列读/删的签名（hex）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
    /// 队列的邀请有效期（毫秒，0/缺省 = 长期）。只对建队列有意义。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_ms: Option<u64>,
    /// `QueueSend` 的密文消息体。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Vec<u8>>,
}

impl Default for MailboxRequest {
    fn default() -> Self {
        Self {
            op: Op::Ping,
            queue: None,
            sender_auth: None,
            owner_auth: None,
            sig: None,
            ttl_ms: None,
            payload: None,
        }
    }
}

impl MailboxRequest {
    /// 健康检查。
    pub fn ping() -> Self {
        Self::default()
    }

    /// 建队列并设置邀请有效期（毫秒；0 = 长期）。
    pub fn queue_create_invite(
        queue: &str,
        sender_auth: &str,
        owner_auth: &str,
        ttl_ms: u64,
    ) -> Self {
        Self {
            ttl_ms: Some(ttl_ms),
            ..Self::queue_create(queue, sender_auth, owner_auth)
        }
    }

    /// 创建接收队列（长期有效）。
    pub fn queue_create(queue: &str, sender_auth: &str, owner_auth: &str) -> Self {
        Self {
            op: Op::QueueCreate,
            queue: Some(queue.to_string()),
            sender_auth: Some(sender_auth.to_string()),
            owner_auth: Some(owner_auth.to_string()),
            ..Self::default()
        }
    }

    /// 向队列投递（`sig` 覆盖 `queue || payload`）。
    pub fn queue_send(queue: &str, payload: Vec<u8>, sig: &str) -> Self {
        Self {
            op: Op::QueueSend,
            queue: Some(queue.to_string()),
            sig: Some(sig.to_string()),
            payload: Some(payload),
            ..Self::default()
        }
    }

    /// 删除队列（`sig` 覆盖 `queue`）。
    pub fn queue_delete(queue: &str, sig: &str) -> Self {
        Self {
            op: Op::QueueDelete,
            queue: Some(queue.to_string()),
            sig: Some(sig.to_string()),
            ..Self::default()
        }
    }

    /// 取走队列消息（`sig` 覆盖 `queue`）。
    pub fn queue_get(queue: &str, sig: &str) -> Self {
        Self {
            op: Op::QueueGet,
            queue: Some(queue.to_string()),
            sig: Some(sig.to_string()),
            ..Self::default()
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Ping,
    /// 创建单向接收队列（邀请创建方调用）。
    QueueCreate,
    /// 向队列投递一条密文（发送方需用 sender key 签名）。
    QueueSend,
    /// 取走队列里的全部消息（只有 owner key 能取）。
    QueueGet,
    /// 删除队列及其消息（只有 owner key 能删）。
    QueueDelete,
}

/// 节点 → 请求方响应。
#[derive(Debug, Serialize, Deserialize)]
pub struct MailboxResponse {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// `QueueGet` 命中的待收密文。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub messages: Option<Vec<StoredMessage>>,
}

/// 存储在邮箱里的密文消息。`to_peer_id` 是历史字段名，现在装的是
/// 队列 id（`msg_id` + 队列 id 才是存储主键）；客户端按队列取，不按人取。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    /// 消息 ID（客户端从加密头 (gen,n) 派生，全局唯一）。
    pub msg_id: String,
    /// 接收方 peer_id（按此分类队列）。
    pub to_peer_id: String,
    /// 应用层加密后的消息内容（含文本与时间）。
    pub msg: Vec<u8>,
}

/// 单次请求的总体超时（拨号 + 写入 + 读响应）。节点失联/无响应时
/// 客户端轮询与节点间同步不能被无限阻塞。
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// 向单个 mailbox 节点发一个请求，返回响应。
pub async fn send_request(
    endpoint: &Endpoint,
    peer_id: &str,
    req: &MailboxRequest,
) -> Result<MailboxResponse> {
    // 允许传 EndpointTicket（带地址，无 DNS 环境用）或纯 peer_id。
    let addr = if let Ok(ticket) = peer_id.parse::<iroh_tickets::endpoint::EndpointTicket>() {
        ticket.endpoint_addr().clone()
    } else {
        let addr_id: iroh::EndpointId = peer_id
            .parse()
            .map_err(|_| anyhow!("invalid peer id or ticket: {peer_id}"))?;
        iroh::EndpointAddr::new(addr_id)
    };
    let conn = tokio::time::timeout(REQUEST_TIMEOUT, endpoint.connect(addr, ALPN))
        .await
        .map_err(|_| anyhow!("connect to {peer_id} timed out"))??;
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(&serde_json::to_vec(req)?).await?;
    send.finish()?;
    let payload = tokio::time::timeout(REQUEST_TIMEOUT, recv.read_to_end(MAX_PAYLOAD))
        .await
        .map_err(|_| anyhow!("waiting response from {peer_id} timed out"))??;
    let resp: MailboxResponse =
        serde_json::from_slice(&payload).map_err(|e| anyhow!("bad mailbox response: {e}"))?;
    Ok(resp)
}

/// 创建一个拨号用 Endpoint（与节点同配置，保证地址可解析）。
pub async fn make_endpoint(secret_key: iroh::SecretKey) -> Result<Endpoint> {
    Ok(Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?)
}

// ===================== 明文填充（抗长度分析） =====================
//
// 消息在棘轮加密前先按「桶」对齐：明文 = magic(4) | len(4 BE) | payload |
// 零填充，总长为 256 / 512 / 1K / 2K / … / 64K 中最小的不小于 payload+8 的桶。
// 接收端按 magic 识别并截取；旧版无 magic 的消息原样返回（向后兼容）。

/// 填充头魔数。
pub const PAD_MAGIC: &[u8; 4] = b"PPAD";
/// 填充头长度：magic + len(u32 BE)。
pub const PAD_HEADER: usize = 8;
/// 最小桶。
pub const PAD_MIN_BUCKET: usize = 256;
/// 最大桶（超过则不再对齐）。
pub const PAD_MAX_BUCKET: usize = 64 * 1024;

fn next_bucket(need: usize) -> usize {
    let mut bucket = PAD_MIN_BUCKET;
    while bucket < need && bucket < PAD_MAX_BUCKET {
        bucket *= 2;
    }
    bucket
}

/// 给明文加长度头并对齐到桶；超长明文按原样加头（不再对齐）。
pub fn pad_plaintext(payload: &[u8]) -> Vec<u8> {
    let need = payload.len() + PAD_HEADER;
    let bucket = next_bucket(need);
    let total = if bucket >= need { bucket } else { need };
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(PAD_MAGIC);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out.resize(total, 0);
    out
}

/// 去掉填充；没有 magic（旧消息）时原样返回。
pub fn unpad_plaintext(data: &[u8]) -> Vec<u8> {
    if data.len() < PAD_HEADER || &data[0..4] != PAD_MAGIC {
        return data.to_vec();
    }
    let len = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;
    if len > data.len() - PAD_HEADER {
        return data.to_vec();
    }
    data[PAD_HEADER..PAD_HEADER + len].to_vec()
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_roundtrip_and_buckets() {
        for len in [0usize, 1, 100, 247, 248, 500, 1000, 5000, 60000] {
            let payload = vec![7u8; len];
            let padded = pad_plaintext(&payload);
            assert_eq!(unpad_plaintext(&padded), payload);
            if len + PAD_HEADER <= PAD_MAX_BUCKET {
                assert_eq!(padded.len() % PAD_MIN_BUCKET, 0, "bucket aligned");
                assert!(padded.len().is_power_of_two());
            }
        }
    }

    #[test]
    fn unpad_legacy_passthrough() {
        let legacy = b"{\"msg_text\":\"hi\"}";
        assert_eq!(unpad_plaintext(legacy), legacy.to_vec());
    }

    #[test]
    fn pad_hides_length() {
        let a = pad_plaintext(&[1u8; 10]);
        let b = pad_plaintext(&[1u8; 200]);
        assert_eq!(a.len(), b.len(), "同桶内长度应一致");
    }

    #[test]
    fn request_roundtrip_serde() {
        let req =
            MailboxRequest::queue_send("00112233445566778899aabbccddeeff", vec![1, 2, 3], "sig");
        let bytes = serde_json::to_vec(&req).unwrap();
        let back: MailboxRequest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.op, Op::QueueSend);
        assert_eq!(back.payload.as_deref(), Some(&[1u8, 2, 3][..]));
        assert_eq!(back.sig.as_deref(), Some("sig"));
    }
}
