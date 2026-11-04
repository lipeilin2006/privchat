//! PrivChat 洋葱路由（Onion Routing）
//!
//! 目标：客户端把一条请求包进多层加密，依次经过若干中继节点逐跳剥离，
//! 每个中继只知道「上一层是谁、下一跳是谁」，不知道完整路径与内容。
//!
//! ## 包结构
//!
//! 每一层（`Layer`）：
//! ```text
//! [0..32]    eph_pub    本层临时 X25519 公钥（发送方生成）
//! [32..44]   nonce      ChaCha20-Poly1305 随机 nonce
//! [44..]     ciphertext 明文 = next(32) || inner_len(u16 LE) || inner
//! ```
//! - `next`：下一跳 peer_id 的 32 字节 Ed25519 公钥；全 0 表示**终点**。
//! - 最内层 `inner` 是真正的请求体（这里放 mailbox PUT 的 JSON）。
//!
//! 加密密钥：`X25519(eph_priv, node_ed25519_pub→Montgomery)` 再经
//! HKDF-SHA256 派生。中继侧用自己 Ed25519 私钥转换出的 X25519 私钥与
//! `eph_pub` 做同样 ECDH，等价得到同一密钥。
//!
//! 由于每层固定多出 94 字节（32+12+16+34），N 跳的包总长为
//! `payload + 94*N`，内层长度上限 65535，因此单包内层有效载荷约 64KB。
//! 大文件按块切分，逐块走洋葱并在接收端重组（见 CLI 的 send-image）。

use anyhow::{anyhow, bail, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// 洋葱中继 ALPN（与 mailbox / 聊天 ALPN 区分）。
pub const ONION_ALPN: &[u8] = b"privchat/onion";

/// 单层固定开销：eph(32) + nonce(12) + tag(16) + next(32) + len(2)。
pub const LAYER_OVERHEAD: usize = 32 + 12 + 16 + 32 + 2;

/// 单包内层有效载荷上限（受 u16 长度字段限制，再含 N 层开销）。
pub const MAX_INNER: usize = 64 * 1024;

const AAD: &[u8] = b"privchat/onion/v1";
const INFO: &[u8] = b"privchat/onion/key/v1";

fn decode_peer(peer_id: &str) -> Result<[u8; 32]> {
    let bytes = hex_decode(peer_id)?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .map_err(|e| anyhow!("invalid peer key {peer_id}: {e}"))?;
    Ok(bytes)
}

fn hex_decode(s: &str) -> Result<[u8; 32]> {
    let raw = s.trim();
    if raw.len() != 64 {
        bail!("peer id 长度应为 64 位十六进制，实际 {}", raw.len());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16)
            .map_err(|e| anyhow!("peer id 非法十六进制: {e}"))?;
    }
    Ok(out)
}

/// 发送方派生某一跳的对称密钥。
fn key_for_sender(eph: &StaticSecret, node_ed_pub: &[u8; 32]) -> Result<[u8; 32]> {
    let peer_ed = ed25519_dalek::VerifyingKey::from_bytes(node_ed_pub)
        .map_err(|e| anyhow!("invalid node key: {e}"))?;
    let node_x = PublicKey::from(peer_ed.to_montgomery().to_bytes());
    let shared = eph.diffie_hellman(&node_x);
    okm(shared.as_bytes())
}

/// 中继侧派生同一跳的对称密钥。
fn key_for_relay(secret: &iroh::SecretKey, eph_pub: &[u8; 32]) -> Result<[u8; 32]> {
    let signing = SigningKey::from_bytes(&secret.to_bytes());
    let own_x: StaticSecret = signing.to_scalar_bytes().into();
    let eph = PublicKey::from(*eph_pub);
    let shared = own_x.diffie_hellman(&eph);
    okm(shared.as_bytes())
}

fn okm(shared: &[u8; 32]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut key = [0u8; 32];
    hk.expand(INFO, &mut key)
        .map_err(|e| anyhow!("hkdf expand failed: {e}"))?;
    Ok(key)
}

/// 把 `payload` 依次包进 `relays` 各层，返回最外层字节。
///
/// `relays` 顺序即路径顺序：`relays[0]` 最先收到包，`relays.last()` 为终点。
pub fn wrap(relays: &[String], payload: &[u8]) -> Result<Vec<u8>> {
    if relays.is_empty() {
        bail!("洋葱路径不能为空");
    }
    if payload.len() > MAX_INNER {
        bail!("单包载荷 {} 超过上限 {}", payload.len(), MAX_INNER);
    }
    // 终点标记：next 全 0。
    let mut data = payload.to_vec();
    for i in (0..relays.len()).rev() {
        let next: [u8; 32] = if i + 1 < relays.len() {
            decode_peer(&relays[i + 1])?
        } else {
            [0u8; 32]
        };
        let mut plain = Vec::with_capacity(34 + data.len());
        plain.extend_from_slice(&next);
        plain.extend_from_slice(&(data.len() as u16).to_le_bytes());
        plain.extend_from_slice(&data);

        let eph = StaticSecret::random_from_rng(OsRng);
        let eph_pub = PublicKey::from(&eph);
        let key = key_for_sender(&eph, &decode_peer(&relays[i])?)?;

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &plain,
                    aad: AAD,
                },
            )
            .map_err(|_| anyhow!("洋葱加密失败"))?;

        let mut layer = Vec::with_capacity(44 + ct.len());
        layer.extend_from_slice(eph_pub.as_bytes());
        layer.extend_from_slice(&nonce_bytes);
        layer.extend_from_slice(&ct);
        data = layer;
    }
    Ok(data)
}

/// 中继剥离一层。返回 `(next_peer_id, inner)`；`next_peer_id` 为 `None` 表示本节点是终点。
pub fn peel(secret: &iroh::SecretKey, packet: &[u8]) -> Result<(Option<String>, Vec<u8>)> {
    if packet.len() < 44 + 16 {
        bail!("洋葱包过短: {} 字节", packet.len());
    }
    let mut eph_pub = [0u8; 32];
    eph_pub.copy_from_slice(&packet[0..32]);
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&packet[32..44]);
    let ct = &packet[44..];

    let key = key_for_relay(secret, &eph_pub)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plain = cipher
        .decrypt(nonce, Payload { msg: ct, aad: AAD })
        .map_err(|_| anyhow!("洋葱剥离失败：密钥不匹配或包被篡改"))?;

    if plain.len() < 34 {
        bail!("洋葱层明文过短");
    }
    let mut next = [0u8; 32];
    next.copy_from_slice(&plain[0..32]);
    let len = u16::from_le_bytes([plain[32], plain[33]]) as usize;
    if plain.len() < 34 + len {
        bail!("洋葱层 inner_len 越界");
    }
    let inner = plain[34..34 + len].to_vec();
    let next_peer = if next.iter().all(|b| *b == 0) {
        None
    } else {
        Some(hex_encode(&next))
    };
    Ok((next_peer, inner))
}

fn hex_encode(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_and_peel_three_hops() {
        let keys: Vec<iroh::SecretKey> = (0..3).map(|_| iroh::SecretKey::generate()).collect();
        let ids: Vec<String> = keys.iter().map(|k| k.public().to_string()).collect();
        let payload = b"{\"op\":\"put\",\"hello\":\"onion\"}";
        let packet = wrap(&ids, payload).unwrap();
        assert_eq!(packet.len(), payload.len() + 3 * LAYER_OVERHEAD);

        // 逐跳剥离
        let (next, inner) = peel(&keys[0], &packet).unwrap();
        assert_eq!(next.as_deref(), Some(ids[1].as_str()));
        let (next, inner) = peel(&keys[1], &inner).unwrap();
        assert_eq!(next.as_deref(), Some(ids[2].as_str()));
        let (next, inner) = peel(&keys[2], &inner).unwrap();
        assert!(next.is_none());
        assert_eq!(inner, payload);
    }

    #[test]
    fn wrong_key_cannot_peel() {
        let a = iroh::SecretKey::generate();
        let b = iroh::SecretKey::generate();
        let ids = vec![a.public().to_string()];
        let packet = wrap(&ids, b"secret").unwrap();
        assert!(peel(&b, &packet).is_err(), "错误节点不能剥离他人层");
    }

    #[test]
    fn tampered_packet_rejected() {
        let a = iroh::SecretKey::generate();
        let ids = vec![a.public().to_string()];
        let mut packet = wrap(&ids, b"hello").unwrap();
        let last = packet.len() - 1;
        packet[last] ^= 0x01;
        assert!(peel(&a, &packet).is_err(), "篡改必须被 AEAD 拒绝");
    }

    #[test]
    fn relays_cannot_see_plaintext() {
        let keys: Vec<iroh::SecretKey> = (0..2).map(|_| iroh::SecretKey::generate()).collect();
        let ids: Vec<String> = keys.iter().map(|k| k.public().to_string()).collect();
        let payload = b"TOP-SECRET-MARKER";
        let packet = wrap(&ids, payload).unwrap();
        assert!(
            !packet.windows(payload.len()).any(|w| w == payload),
            "最外层不能出现明文"
        );
        let (_, inner) = peel(&keys[0], &packet).unwrap();
        assert!(
            !inner.windows(payload.len()).any(|w| w == payload),
            "中间层也不能出现明文"
        );
    }
}
