//! Layer 2.5 · 端到端加密层 (E2EE for Mailbox) — 双棘轮前向保密
//!
//! mailbox 节点是独立的 TLS 端点，能看见直连通道之外的明文。为保证离线
//! 消息的端到端保密，客户端在 PUT 到 mailbox 之前先做**应用层加密**。
//! 本层实现对称链 + 收敛性 DH 刷新的双棘轮方案：
//!
//! - **root₀**：静态 X25519 ECDH（本端长期密钥 Ed25519→X25519，对方 peer_id
//!   Ed25519 公钥→Montgomery）经 HKDF 派生。双方独立计算得到同一根密钥。
//! - **双链分离**：从每个 gen 的 root 经 HKDF 确定性派生两条单向链，按双方
//!   公钥字典序标 `low`/`high`：公钥小者的发送链 = low 方向链，大者的发送链
//!   = high 方向链。因此双方各自算出同一对 (send_ck, recv_ck)，并发首发
//!   不会互相打乱对方链。
//! - **gen 与收敛性 DH 刷新**：每次消息头携带当前 gen、本端本代 eph 公钥
//!   （`dh_pub`）与刷新所用的**上一代 eph 公钥**（`prev_eph`）。当本端
//!   **已在本代发送过**（send_n>0）且**已收到对方本代 eph** 时，下次发送前
//!   刷新：`root_{g+1} = KDF_RK(root_g, DH(my_eph_g, their_eph_g))`。
//!   X25519 对称性（DH(a,b)==DH(b,a)）保证双方得到同一新 root。首次发送
//!   时必须先发本代消息 announce 自己的 eph（send_n==0 不刷新），否则对方
//!   无法还原新 root。接收方若发现对方领先一代（`header.gen == gen+1`），
//!   用**消息头里的 `prev_eph`**（即对方刷新所用的旧 eph 公钥）配合本端
//!   本代 eph 私钥做收敛刷新——即使从未收到对方旧代消息（离线/乱序漏收）
//!   也能还原同一 root，这正是 header 冗余 `prev_eph` 的意义。
//! - **滑动窗口（skipped 池）**：同代乱序 / 跨代迟到的消息密钥暂存于
//!   `(gen, n) -> mk` 池，取用后即销毁；窗口 `MAX_SKIP` 限制单次前跳，
//!   池容量 `SKIPPED_MAX` 防 DoS。
//! - **会话持久化**：`to_bytes`/`from_bytes` 序列化状态（不含长期私钥），
//!   由 store 表 `ratchets(local_id, peer_id, state)` 保存，重启后续链。
//!
//! - **gen0 绑定（X3DH 式）**：gen0 的两条链不再是「裸 root0 直接派生」，
//!   而是把发送方本代临时 eph 混进去：`ck = HKDF(root, DH(eph, pk_peer))`。
//!   接收方用对端 header 里的 `dh_pub`（或换代时的 `prev_eph`）做对称的
//!   `DH(sk_own, eph_peer)` 还原同一条链。这样即使**长期私钥泄漏**，
//!   攻击者也拿不到 gen0 消息的密钥 —— 还需要临时 eph 私钥。
//!   gen>=1 的链仍由刷新后的 root 直接派生（FS 由 DH 刷新保证）。
//!
//! 消息 blob 格式（存 mailbox / 走 wire 的 `msg`）：
//! ```text
//! [0..4] magic "PRR4" | [4] version=6 | [5..9] gen u32LE
//! [9..41] dh_pub (32) | [41..45] n u32LE | [45..49] pn u32LE
//! [49..81] prev_eph (32) | [81..93] nonce (12) | [93..] ChaCha20-Poly1305 ciphertext
//! [len-64..] Ed25519 签名（覆盖 header + ciphertext）
//! ```
//! 固定前缀 93 字节（gen 为 u32，杜绝刷新回绕），完整头作为 AEAD AAD
//! 认证；末尾 64 字节是发送方专属身份的 Ed25519 签名，收端**先验签再动
//! 棘轮状态**。签名把「这条消息确实出自该联系人身份」显式绑到每条消息，
//! 也挡住实现层把消息解到错误会话上的问题。mailbox 只接触密文。

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use rand_core::RngCore;
use sha2::{Digest, Sha256};

pub(super) mod header;
pub(super) mod hex;
pub(super) mod invite;
pub(super) mod ratchet;
pub(super) mod x3dh;

pub use header::header_opk_id;
pub use hex::{hex_decode, hex_encode};
pub use invite::{encode_invite, parse_invite};
pub use ratchet::Ratchet;

use x3dh::{new_eph, x25519_shared, x3dh_root_initiator, x3dh_root_responder};

use header::{parse_header, Header, HEADER_LEN, MAGIC, SIG_LEN, VERSION};
/// 单次前跳 / 跨代快进的最大窗口。
const MAX_SKIP: u32 = 200;
/// skipped 池容量上限（防 DoS）。
const SKIPPED_MAX: usize = 1000;

const INFO_ROOT: &[u8] = b"privchat/session/root/v1";
const INFO_RK: &[u8] = b"privchat/ratchet/rk/v1";
const INFO_CK: &[u8] = b"privchat/ratchet/ck/v1";
const INFO_CHAIN_LOW: &[u8] = b"privchat/ratchet/chain/low";
const INFO_CHAIN_HIGH: &[u8] = b"privchat/ratchet/chain/high";
/// 每消息签名的域分隔前缀（防跨协议重放）。
const INFO_MSG_SIG: &[u8] = b"privchat/msg/sig/v1";

/// 会话标识：`H("privchat/session/id/v1" || IK_lo || IK_hi || EK_initiator)`。
///
/// 双方都能算：IK 是双方身份公钥（排序后拼接），EK 是发起方首条消息里的
/// 临时公钥。并发发起时按这个 ID 字典序取小者为主会话，两边结果一致。
pub fn session_id(ek: &[u8; 32], a_ik: &[u8; 32], b_ik: &[u8; 32]) -> String {
    let (lo, hi) = if a_ik < b_ik {
        (a_ik, b_ik)
    } else {
        (b_ik, a_ik)
    };
    let mut h = Sha256::new();
    h.update(b"privchat/session/id/v1");
    h.update(lo);
    h.update(hi);
    h.update(ek);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// 把 peer_id（hex 的 Ed25519 公钥）解成原始 32 字节，供 session_id 使用。
pub fn peer_pub_bytes(peer_id: &str) -> Result<[u8; 32]> {
    decode_peer_pub(peer_id)
}

/// 从消息头取发起方的会话 EK：gen0 用 `dh_pub`，gen1 用 `prev_eph`。
pub fn header_ek(blob: &[u8]) -> Result<[u8; 32]> {
    let hdr = parse_header(blob)?;
    match hdr.gen {
        0 => Ok(hdr.dh_pub),
        1 => Ok(hdr.prev_eph),
        gen => Err(anyhow!("cannot recover EK from gen {gen}")),
    }
}

/// 收敛性 DH 刷新：`root' = KDF_RK(root, DH)`。
fn kdf_rk(root: &[u8; 32], dh: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(root), dh);
    let mut out = [0u8; 32];
    hk.expand(INFO_RK, &mut out)
        .expect("hkdf expand 32 bytes cannot fail");
    out
}

/// 链密钥推进：`(ck', mk) = KDF_CK(ck)`。
fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(ck), &[]);
    let mut out = [0u8; 64];
    hk.expand(INFO_CK, &mut out)
        .expect("hkdf expand 64 bytes cannot fail");
    let mut next = [0u8; 32];
    let mut mk = [0u8; 32];
    next.copy_from_slice(&out[..32]);
    mk.copy_from_slice(&out[32..]);
    (next, mk)
}

/// 从 root 派生双链：公钥小者的发送链 = low 方向链，大者 = high 方向链。
fn derive_chains(root: &[u8; 32], own_pub: &[u8; 32], peer_pub: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(None, root);
    let mut low = [0u8; 32];
    let mut high = [0u8; 32];
    hk.expand(INFO_CHAIN_LOW, &mut low)
        .expect("hkdf expand 32 bytes cannot fail");
    hk.expand(INFO_CHAIN_HIGH, &mut high)
        .expect("hkdf expand 32 bytes cannot fail");
    if own_pub < peer_pub {
        (low, high)
    } else {
        (high, low)
    }
}

fn decrypt_aead(mk: &[u8; 32], header: &Header, blob: &[u8], body_end: usize) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(mk));
    cipher
        .decrypt(
            Nonce::from_slice(&header.nonce),
            Payload {
                msg: &blob[header.len..body_end],
                aad: &blob[..header.len],
            },
        )
        .map_err(|e| anyhow!("decrypt failed: {e}"))
}

/// 对 `body`（header + ciphertext）做 Ed25519 签名，返回 64 字节。
fn sign_body(own: &iroh::SecretKey, body: &[u8]) -> [u8; SIG_LEN] {
    use ed25519_dalek::Signer;
    let signing: SigningKey = SigningKey::from_bytes(&own.to_bytes());
    let mut msg = Vec::with_capacity(INFO_MSG_SIG.len() + body.len());
    msg.extend_from_slice(INFO_MSG_SIG);
    msg.extend_from_slice(body);
    signing.sign(&msg).to_bytes()
}

/// 用对端身份公钥验证签名（覆盖 header + ciphertext，含域分隔）。
fn verify_body(peer_pub: &[u8; 32], body: &[u8], sig_bytes: &[u8]) -> Result<()> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(peer_pub)
        .map_err(|e| anyhow!("invalid peer key: {e}"))?;
    let sig_arr: [u8; SIG_LEN] = sig_bytes
        .try_into()
        .map_err(|_| anyhow!("bad signature length: {}", sig_bytes.len()))?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    let mut msg = Vec::with_capacity(INFO_MSG_SIG.len() + body.len());
    msg.extend_from_slice(INFO_MSG_SIG);
    msg.extend_from_slice(body);
    vk.verify_strict(&msg, &sig)
        .map_err(|_| anyhow!("message signature verification failed"))
}

fn insert_skipped(
    pool: &mut HashMap<(u32, u32), [u8; 32]>,
    key: (u32, u32),
    mk: [u8; 32],
) -> Result<()> {
    if !pool.contains_key(&key) {
        if pool.len() >= SKIPPED_MAX {
            return Err(anyhow!("skipped pool full"));
        }
        pool.insert(key, mk);
    }
    Ok(())
}

/// 解码对端 peer_id（hexlower 的 Ed25519 公钥）为 32 字节。
fn decode_peer_pub(peer_id: &str) -> Result<[u8; 32]> {
    if peer_id.len() != 64 {
        return Err(anyhow!(
            "peer id must be 64 hex chars, got {}",
            peer_id.len()
        ));
    }
    let bytes: [u8; 32] = hex_decode(peer_id)?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("peer id must be 64 hex chars"))?;
    // 校验是合法 Ed25519 公钥（防注入）。
    ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .map_err(|e| anyhow!("invalid peer key: {e}"))?;
    Ok(bytes)
}

fn read_u8(bytes: &[u8], pos: &mut usize) -> Result<u8> {
    let b = *bytes.get(*pos).ok_or_else(|| anyhow!("truncated state"))?;
    *pos += 1;
    Ok(b)
}

fn read_u32(bytes: &[u8], pos: &mut usize) -> Result<u32> {
    let end = pos
        .checked_add(4)
        .ok_or_else(|| anyhow!("state length overflow"))?;
    let slice = bytes
        .get(*pos..end)
        .ok_or_else(|| anyhow!("truncated state"))?;
    *pos = end;
    Ok(u32::from_le_bytes(slice.try_into().unwrap()))
}

fn read_fixed<const N: usize>(bytes: &[u8], pos: &mut usize) -> Result<[u8; N]> {
    let end = pos
        .checked_add(N)
        .ok_or_else(|| anyhow!("state length overflow"))?;
    let slice = bytes
        .get(*pos..end)
        .ok_or_else(|| anyhow!("truncated state"))?;
    *pos = end;
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    Ok(out)
}

#[cfg(test)]
mod tests;
