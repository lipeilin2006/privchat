//! 邀请串：`pc1:` + hex(IK || SPK || sig || ticket || OPK 列表)。
//!
//! 签名覆盖 `IK || SPK || OPK 列表`，收方验签后即可确认这些密钥都属于该 IK。

use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;

use super::hex::{hex_decode, hex_encode};

/// 邀请串前缀。
const INVITE_PREFIX: &str = "pc1:";
/// 邀请串签名的域分隔前缀。
const INFO_INVITE: &[u8] = b"privchat/invite/v1";

/// 邀请串 = `pc1:` + hex(
///   IK(32) || SPK(32) || sig(64) ||
///   u16 ticket_len || ticket ||
///   u16 opk_count || (u64 id || 32B opk_pub)*
/// )。
pub fn encode_invite(
    own: &iroh::SecretKey,
    spk_pk: &[u8; 32],
    ticket: Option<&str>,
    opks: &[(u64, [u8; 32])],
) -> String {
    let mut signed = Vec::with_capacity(64 + opks.len() * 40);
    signed.extend_from_slice(own.public().as_bytes());
    signed.extend_from_slice(spk_pk);
    for (id, pk) in opks {
        signed.extend_from_slice(&id.to_le_bytes());
        signed.extend_from_slice(pk);
    }
    let mut msg = INFO_INVITE.to_vec();
    msg.extend_from_slice(&signed);
    let signing: SigningKey = SigningKey::from_bytes(&own.to_bytes());
    use ed25519_dalek::Signer;
    let sig = signing.sign(&msg).to_bytes();

    let mut body = Vec::with_capacity(signed.len() + 64 + 2 + 2);
    body.extend_from_slice(&signed[..64]);
    body.extend_from_slice(&sig);
    let ticket = ticket.unwrap_or_default().as_bytes();
    body.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
    body.extend_from_slice(ticket);
    body.extend_from_slice(&(opks.len() as u16).to_be_bytes());
    for (id, pk) in opks {
        body.extend_from_slice(&id.to_le_bytes());
        body.extend_from_slice(pk);
    }
    format!("{INVITE_PREFIX}{}", hex_encode(&body))
}

/// 解析并验证邀请串，返回 `(peer_id(hex), SPK_pub, ticket, OPK 列表)`。
pub fn parse_invite(
    invite: &str,
) -> Result<(String, [u8; 32], Option<String>, Vec<(u64, [u8; 32])>)> {
    let raw = invite
        .trim()
        .strip_prefix(INVITE_PREFIX)
        .ok_or_else(|| anyhow!("invite must start with {INVITE_PREFIX}"))?;
    let bytes = hex_decode(raw)?;
    if bytes.len() < 130 {
        return Err(anyhow!("bad invite length: {}", bytes.len()));
    }
    let ik: [u8; 32] = bytes[..32].try_into().unwrap();
    let spk: [u8; 32] = bytes[32..64].try_into().unwrap();
    let sig: [u8; 64] = bytes[64..128].try_into().unwrap();
    let ticket_len = u16::from_be_bytes([bytes[128], bytes[129]]) as usize;
    let mut pos = 130;
    if bytes.len() < pos + ticket_len + 2 {
        return Err(anyhow!("bad invite ticket length"));
    }
    let ticket = if ticket_len == 0 {
        None
    } else {
        Some(
            String::from_utf8(bytes[pos..pos + ticket_len].to_vec())
                .map_err(|_| anyhow!("invite ticket is not utf8"))?,
        )
    };
    pos += ticket_len;
    let opk_count = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
    pos += 2;
    if bytes.len() != pos + opk_count * 40 {
        return Err(anyhow!("bad invite opk section"));
    }
    let mut opks = Vec::with_capacity(opk_count);
    for i in 0..opk_count {
        let base = pos + i * 40;
        let id = u64::from_le_bytes(bytes[base..base + 8].try_into().unwrap());
        let pk: [u8; 32] = bytes[base + 8..base + 40].try_into().unwrap();
        opks.push((id, pk));
    }

    // 验签：覆盖 IK||SPK||OPK 列表。
    let mut signed = Vec::with_capacity(64 + opks.len() * 40);
    signed.extend_from_slice(&ik);
    signed.extend_from_slice(&spk);
    for (id, pk) in &opks {
        signed.extend_from_slice(&id.to_le_bytes());
        signed.extend_from_slice(pk);
    }
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&ik)
        .map_err(|e| anyhow!("invalid invite identity key: {e}"))?;
    let mut msg = INFO_INVITE.to_vec();
    msg.extend_from_slice(&signed);
    vk.verify_strict(&msg, &ed25519_dalek::Signature::from_bytes(&sig))
        .map_err(|_| anyhow!("invite signature verification failed"))?;
    Ok((hex_encode(&ik), spk, ticket, opks))
}
