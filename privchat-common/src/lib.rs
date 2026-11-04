//! PrivChat 共享协议层：mailbox 客户端与 mailbox 节点之间的 wire 协议与 PoW。
//!
//! 客户端（`privchat-client`）与节点（`privchat-mailbox`）各自依赖本 crate，
//! 保证请求/响应结构与常量只维护一份，避免两处复制导致漂移。
//!
//! 协议：每条 QUIC bi-stream 一次请求。客户端写入 JSON 的
//! [`MailboxRequest`]，节点写回 JSON 的 [`MailboxResponse`]。
//! 可选操作码见 [`Op`]：`put`/`fetch` 由客户端使用；
//! `sync`/`sync_ack` 由节点间组网同步使用，`ping` 用于健康检查。

use anyhow::{anyhow, Result};
use iroh::endpoint::presets;
use iroh::Endpoint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// mailbox 节点唯一 ALPN：与客户端聊天 ALPN 区分。
pub const ALPN: &[u8] = b"privchat/mailbox";

/// 单条邮件容量上限（密文，含 overhead）。
pub const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

/// PoW 难度：`SHA-256(to || payload || nonce)` 摘要的前导零**字节**数。
///
/// 平均约 `256^1 = 256` 次尝试，秒级完成，但足以把灌垃圾的成本抬高一个
/// 数量级。仅客户端 → 节点 `put` 需要；节点间 `sync` 走内部通道，不验证。
pub const POW_DIFFICULTY: usize = 1;

/// 计算一次 PoW 挑战的摘要输入：`to || payload || nonce`（nonce 小端 8 字节）。
fn pow_input(to: &str, payload: &[u8], nonce: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(to.len() + payload.len() + 8);
    buf.extend_from_slice(to.as_bytes());
    buf.extend_from_slice(payload);
    buf.extend_from_slice(&nonce.to_le_bytes());
    buf
}

/// 校验 nonce 是否满足 PoW 难度。
pub fn verify_pow(to: &str, payload: &[u8], nonce: u64) -> bool {
    let digest = Sha256::digest(pow_input(to, payload, nonce));
    digest[..POW_DIFFICULTY].iter().all(|&b| b == 0)
}

/// 暴力搜索满足难度的 nonce（从 0 递增）。对 1 字节难度平均 256 次。
pub fn find_pow(to: &str, payload: &[u8]) -> u64 {
    let mut nonce = 0u64;
    loop {
        if verify_pow(to, payload, nonce) {
            return nonce;
        }
        nonce = nonce.wrapping_add(1);
    }
}

/// 请求方 → 节点请求。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxRequest {
    #[serde(rename = "op")]
    pub op: Op,
    /// put 的接收方 peer_id / sync_ack 的目标接收方。
    #[serde(rename = "to", default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// fetch 的目标接收方 peer_id。
    #[serde(rename = "for", default, skip_serializing_if = "Option::is_none")]
    pub for_peer: Option<String>,
    /// put 的消息 ID（发送方从加密头 (gen,n) 派生的逻辑发送序）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// fetch 返回后广播删除 / sync_ack 的消息 ID 列表。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
    /// put 的密文消息体。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Vec<u8>>,
    /// put 的工作量证明 nonce。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
    /// sync 广播的完整消息。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub msg: Option<StoredMessage>,
    /// 单向队列 id（16 字节，hex）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue: Option<String>,
    /// 队列创建时登记的 sender 公钥 / owner 公钥（hex）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_auth: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_auth: Option<String>,
    /// 队列操作签名（hex，Ed25519）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

impl MailboxRequest {
    pub fn put(to: &str, id: &str, payload: Vec<u8>, nonce: u64) -> Self {
        Self {
            op: Op::Put,
            to: Some(to.to_string()),
            for_peer: None,
            id: Some(id.to_string()),
            ids: None,
            payload: Some(payload),
            nonce: Some(nonce),
            msg: None,
            queue: None,
            sender_auth: None,
            owner_auth: None,
            sig: None,
        }
    }

    /// 创建接收队列。
    pub fn queue_create(queue: &str, sender_auth: &str, owner_auth: &str) -> Self {
        Self {
            op: Op::QueueCreate,
            to: None,
            for_peer: None,
            id: None,
            ids: None,
            payload: None,
            nonce: None,
            msg: None,
            queue: Some(queue.to_string()),
            sender_auth: Some(sender_auth.to_string()),
            owner_auth: Some(owner_auth.to_string()),
            sig: None,
        }
    }

    /// 向队列投递（`sig` 覆盖 `queue || payload`）。
    pub fn queue_send(queue: &str, payload: Vec<u8>, sig: &str) -> Self {
        Self {
            op: Op::QueueSend,
            to: None,
            for_peer: None,
            id: None,
            ids: None,
            payload: Some(payload),
            nonce: None,
            msg: None,
            queue: Some(queue.to_string()),
            sender_auth: None,
            owner_auth: None,
            sig: Some(sig.to_string()),
        }
    }

    /// 取走队列消息（`sig` 覆盖 `queue`）。
    pub fn queue_get(queue: &str, sig: &str) -> Self {
        Self {
            op: Op::QueueGet,
            to: None,
            for_peer: None,
            id: None,
            ids: None,
            payload: None,
            nonce: None,
            msg: None,
            queue: Some(queue.to_string()),
            sender_auth: None,
            owner_auth: None,
            sig: Some(sig.to_string()),
        }
    }

    /// 删除队列（`sig` 覆盖 `queue`）。
    pub fn queue_delete(queue: &str, sig: &str) -> Self {
        Self {
            op: Op::QueueDelete,
            to: None,
            for_peer: None,
            id: None,
            ids: None,
            payload: None,
            nonce: None,
            msg: None,
            queue: Some(queue.to_string()),
            sender_auth: None,
            owner_auth: None,
            sig: Some(sig.to_string()),
        }
    }

    /// 邻居交换请求：索取对方已知的 mailbox 列表。
    pub fn peers() -> Self {
        Self {
            op: Op::Peers,
            to: None,
            for_peer: None,
            id: None,
            ids: None,
            payload: None,
            nonce: None,
            msg: None,
            queue: None,
            sender_auth: None,
            owner_auth: None,
            sig: None,
        }
    }

    pub fn fetch(for_peer: &str) -> Self {
        Self {
            op: Op::Fetch,
            to: None,
            for_peer: Some(for_peer.to_string()),
            id: None,
            ids: None,
            payload: None,
            nonce: None,
            msg: None,
            queue: None,
            sender_auth: None,
            owner_auth: None,
            sig: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Put,
    Fetch,
    Ping,
    /// 邻居交换：请求方询问节点已知的 mailbox 列表（PEX）。
    Peers,
    Sync,
    SyncAck,
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
    /// fetch 命中的待收密文。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub messages: Option<Vec<StoredMessage>>,
    /// `peers` 操作返回的已知 mailbox 列表（PEX）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peers: Option<Vec<String>>,
}

/// 存储在邮箱里的密文消息。`to_peer_id` 是接收方的专属身份（各联系人
/// 身份互不相同），节点按它分类队列；`from` 可省——队列只属于唯一一个
/// 发送方，接收方由自己的 `local_id` 在联系人表唯一推出对方 peer_id。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    /// 消息 ID（客户端从加密头 (gen,n) 派生，全局唯一）。
    pub msg_id: String,
    /// 接收方 peer_id（按此分类队列）。
    pub to_peer_id: String,
    /// 应用层加密后的消息内容（含文本与时间）。
    pub msg: Vec<u8>,
}

impl StoredMessage {
    /// 从 put 请求解析出完整消息。
    pub fn from_request(r: &MailboxRequest) -> Result<Self> {
        Ok(Self {
            msg_id: r.id.clone().ok_or_else(|| anyhow!("put missing id"))?,
            to_peer_id: r.to.clone().ok_or_else(|| anyhow!("put missing to"))?,
            msg: r
                .payload
                .clone()
                .ok_or_else(|| anyhow!("put missing payload"))?,
        })
    }
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
    fn find_pow_yields_valid_nonce() {
        let to = "recipient-peer-id";
        let payload = b"ciphertext payload".to_vec();
        let nonce = find_pow(to, &payload);
        assert!(verify_pow(to, &payload, nonce));
    }

    #[test]
    fn verify_pow_rejects_wrong_nonce() {
        let to = "recipient-peer-id";
        let payload = b"ciphertext payload".to_vec();
        let nonce = find_pow(to, &payload);
        assert!(
            !verify_pow(to, &payload, nonce.wrapping_add(1)),
            "neighbor nonce must fail"
        );
        // 改 payload 后原 nonce 不应再有效。
        let other = b"different payload".to_vec();
        assert!(
            !verify_pow(to, &other, nonce),
            "payload change must invalidate nonce"
        );
    }

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
        let a = pad_plaintext(&vec![1u8; 10]);
        let b = pad_plaintext(&vec![1u8; 200]);
        assert_eq!(a.len(), b.len(), "同桶内长度应一致");
    }

    #[test]
    fn request_roundtrip_serde() {
        let req = MailboxRequest::put("to-peer", "msg-1", vec![1, 2, 3], 42);
        let bytes = serde_json::to_vec(&req).unwrap();
        let back: MailboxRequest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.op, Op::Put);
        assert_eq!(back.to.as_deref(), Some("to-peer"));
        assert_eq!(back.id.as_deref(), Some("msg-1"));
        assert_eq!(back.payload.as_deref(), Some(&[1u8, 2, 3][..]));
        assert_eq!(back.nonce, Some(42));
    }
}
