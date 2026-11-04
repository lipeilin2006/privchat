//! X3DH 的三组 DH，以及 X25519 / 密钥转换工具。

use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use rand_core::RngCore;
use sha2::Sha256;
use x25519_dalek::StaticSecret;

use super::INFO_ROOT;

/// X3DH 三组 DH 混合成 root₀（发起方）。
///   dh1 = DH(IK_own, SPK_peer)
///   dh2 = DH(EK,     IK_peer)
///   dh3 = DH(EK,     SPK_peer)
pub(super) fn x3dh_root_initiator(
    own: &iroh::SecretKey,
    peer_pub: &[u8; 32],
    peer_spk: &[u8; 32],
    ek_priv: &[u8; 32],
) -> Result<[u8; 32]> {
    let own_ik = own_x25519_secret(own);
    let peer_ik = peer_montgomery(peer_pub)?;
    let dh1 = x25519_shared(&own_ik, peer_spk)?;
    let dh2 = x25519_shared(ek_priv, &peer_ik)?;
    let dh3 = x25519_shared(ek_priv, peer_spk)?;
    Ok(x3dh_mix(&dh1, &dh2, &dh3))
}

/// X3DH 三组 DH 混合成 root₀（响应方，与发起方逐项相等）。
///   dh1 = DH(SPK_own, IK_peer)
///   dh2 = DH(IK_own,  EK_peer)
///   dh3 = DH(SPK_own, EK_peer)
pub(super) fn x3dh_root_responder(
    own: &iroh::SecretKey,
    peer_pub: &[u8; 32],
    own_spk_sk: &[u8; 32],
    ek_pub: &[u8; 32],
) -> Result<[u8; 32]> {
    let own_ik = own_x25519_secret(own);
    let peer_ik = peer_montgomery(peer_pub)?;
    let dh1 = x25519_shared(own_spk_sk, &peer_ik)?;
    let dh2 = x25519_shared(&own_ik, ek_pub)?;
    let dh3 = x25519_shared(own_spk_sk, ek_pub)?;
    Ok(x3dh_mix(&dh1, &dh2, &dh3))
}

/// 三组 DH 按固定顺序拼起来做 HKDF，双方必须完全一致。
fn x3dh_mix(dh1: &[u8; 32], dh2: &[u8; 32], dh3: &[u8; 32]) -> [u8; 32] {
    let mut ikm = [0u8; 96];
    ikm[..32].copy_from_slice(dh1);
    ikm[32..64].copy_from_slice(dh2);
    ikm[64..].copy_from_slice(dh3);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut root = [0u8; 32];
    hk.expand(INFO_ROOT, &mut root)
        .expect("hkdf expand 32 bytes cannot fail");
    root
}

/// 生成新的临时 X25519 密钥对（私钥 + 公钥字节）。
pub(super) fn new_eph() -> ([u8; 32], [u8; 32]) {
    let mut seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    let secret = StaticSecret::from(seed);
    let public = x25519_dalek::PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}
/// X25519 共享密钥（DH(a,b)==DH(b,a)，收敛刷新与 gen0 绑定的关键）。
///
/// 输出全 0 说明对端给的是低阶点（`dh_pub` / `prev_eph` 未做点校验时
/// 会被利用来把 DH 退化成一个公开值），一律按错误处理。
pub(super) fn x25519_shared(priv_bytes: &[u8; 32], pub_bytes: &[u8; 32]) -> Result<[u8; 32]> {
    let secret = StaticSecret::from(*priv_bytes);
    let public = x25519_dalek::PublicKey::from(*pub_bytes);
    let shared = *secret.diffie_hellman(&public).as_bytes();
    if shared.iter().all(|byte| *byte == 0) {
        return Err(anyhow!(
            "x25519 shared secret is all-zero (low-order point?)"
        ));
    }
    Ok(shared)
}
/// 本端 Ed25519 长期私钥对应的 X25519 私钥（与 `root0` 中的转换一致）。
pub(super) fn own_x25519_secret(own: &iroh::SecretKey) -> [u8; 32] {
    let signing: SigningKey = SigningKey::from_bytes(&own.to_bytes());
    signing.to_scalar_bytes()
}
/// 对端 Ed25519 公钥的 Montgomery 形式（X25519 用）。
pub(super) fn peer_montgomery(peer_pub: &[u8; 32]) -> Result<[u8; 32]> {
    let peer_ed = ed25519_dalek::VerifyingKey::from_bytes(peer_pub)
        .map_err(|e| anyhow!("invalid peer key: {e}"))?;
    Ok(peer_ed.to_montgomery().to_bytes())
}
