//! 连接层（SimpleX 式单向队列）：邀请编解码、队列操作签名、连接状态。
//!
//! 一条连接 = 两条单向队列：
//! - 入站队列：别人写、我用 owner key 读；邀请里带着它的地址与 sender key；
//! - 出站队列：对方建好后在首条消息里告诉我，我用它的 sender key 写。
//!
//! 这一层只做「数据 + 编解码 + 签名」，网络调用留给上层（便于单测）。

use anyhow::{anyhow, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// 邀请串前缀。
const PREFIX: &str = "px1:";
/// 队列操作的签名域（必须与 mailbox 端一致）。
pub const DOMAIN_SEND: &[u8] = b"privchat/queue/send/v1";
pub const DOMAIN_GET: &[u8] = b"privchat/queue/get/v1";
pub const DOMAIN_DELETE: &[u8] = b"privchat/queue/delete/v1";

/// 邀请：告诉对方「往哪条队列写、用什么 key 写、用哪把 E2E 公钥」。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    /// mailbox 节点的 peer_id（hex 32 字节）。
    pub mailbox: String,
    /// 接收队列 id（16 字节）。
    pub queue_id: [u8; 16],
    /// 邀请创建方的连接公钥（X25519）。
    pub owner_ek: [u8; 32],
    /// 允许写这条队列的 sender 私钥（Ed25519）。
    ///
    /// 邀请本身就是「写权限」：拿到邀请的人才能往这条队列投递；
    /// 交换完成后 owner 可以换掉队列的 sender key 来收回权限。
    pub sender_sk: [u8; 32],
    /// 可选拨号票据（无 DNS 环境用）。
    pub ticket: Option<String>,
}

impl Invite {
    /// 编码为 `px1:` + base64url。
    pub fn encode(&self) -> String {
        let mut body = Vec::with_capacity(112 + self.ticket.as_ref().map_or(0, |t| t.len() + 2));
        body.extend_from_slice(&self.queue_id);
        body.extend_from_slice(&self.owner_ek);
        body.extend_from_slice(&self.sender_sk);
        let mailbox = hex_decode(&self.mailbox).unwrap_or_else(|_| vec![0u8; 32]);
        body.extend_from_slice(&mailbox);
        let ticket = self.ticket.as_deref().unwrap_or_default().as_bytes();
        body.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
        body.extend_from_slice(ticket);
        format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(&body))
    }

    /// 解析并校验长度。
    pub fn decode(s: &str) -> Result<Self> {
        let raw = s
            .trim()
            .strip_prefix(PREFIX)
            .ok_or_else(|| anyhow!("invite must start with {PREFIX}"))?;
        let bytes = URL_SAFE_NO_PAD
            .decode(raw)
            .map_err(|_| anyhow!("invite is not valid base64"))?;
        if bytes.len() < 112 + 2 {
            return Err(anyhow!("invite too short: {}", bytes.len()));
        }
        let queue_id: [u8; 16] = bytes[..16].try_into().unwrap();
        let owner_ek: [u8; 32] = bytes[16..48].try_into().unwrap();
        let sender_sk: [u8; 32] = bytes[48..80].try_into().unwrap();
        let mailbox_bytes: [u8; 32] = bytes[80..112].try_into().unwrap();
        let ticket_len = u16::from_be_bytes([bytes[112], bytes[113]]) as usize;
        if bytes.len() != 114 + ticket_len {
            return Err(anyhow!("invite ticket length mismatch"));
        }
        let ticket = if ticket_len == 0 {
            None
        } else {
            Some(
                String::from_utf8(bytes[114..].to_vec())
                    .map_err(|_| anyhow!("invite ticket is not utf8"))?,
            )
        };
        Ok(Self {
            mailbox: hex_encode(&mailbox_bytes),
            queue_id,
            owner_ek,
            sender_sk,
            ticket,
        })
    }
}

/// 队列的两把钥匙：sender 用来写，owner 用来读/删。
#[derive(Debug, Clone)]
pub struct QueueKeys {
    pub sender: SigningKey,
    pub owner: SigningKey,
}

impl QueueKeys {
    pub fn generate() -> Self {
        Self {
            sender: random_signing_key(),
            owner: random_signing_key(),
        }
    }

    pub fn from_bytes(sender: [u8; 32], owner: [u8; 32]) -> Self {
        Self {
            sender: SigningKey::from_bytes(&sender),
            owner: SigningKey::from_bytes(&owner),
        }
    }

    pub fn to_bytes(&self) -> ([u8; 32], [u8; 32]) {
        (self.sender.to_bytes(), self.owner.to_bytes())
    }

    pub fn sender_pub_hex(&self) -> String {
        hex_encode(self.sender.verifying_key().as_bytes())
    }

    pub fn owner_pub_hex(&self) -> String {
        hex_encode(self.owner.verifying_key().as_bytes())
    }
}

/// 对「往队列写」签名（覆盖 domain || queue_id || payload）。
pub fn sign_send(queue_id: &[u8; 16], payload: &[u8], sender: &SigningKey) -> String {
    let mut msg = DOMAIN_SEND.to_vec();
    msg.extend_from_slice(queue_id);
    msg.extend_from_slice(payload);
    hex_encode(&sender.sign(&msg).to_bytes())
}

/// 对「读队列」签名（覆盖 domain || queue_id）。
pub fn sign_get(queue_id: &[u8; 16], owner: &SigningKey) -> String {
    let mut msg = DOMAIN_GET.to_vec();
    msg.extend_from_slice(queue_id);
    hex_encode(&owner.sign(&msg).to_bytes())
}

/// 对「删队列」签名（覆盖 domain || queue_id）。
pub fn sign_delete(queue_id: &[u8; 16], owner: &SigningKey) -> String {
    let mut msg = DOMAIN_DELETE.to_vec();
    msg.extend_from_slice(queue_id);
    hex_encode(&owner.sign(&msg).to_bytes())
}

/// 本地校验签名（测试与调试用；节点侧有同样的实现）。
pub fn verify(
    pubkey: &[u8; 32],
    domain: &[u8],
    queue_id: &[u8; 16],
    payload: Option<&[u8]>,
    sig_hex: &str,
) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let Ok(sig_bytes) = hex_decode(sig_hex) else {
        return false;
    };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else {
        return false;
    };
    let mut msg = domain.to_vec();
    msg.extend_from_slice(queue_id);
    if let Some(p) = payload {
        msg.extend_from_slice(p);
    }
    vk.verify_strict(&msg, &Signature::from_bytes(&sig_arr))
        .is_ok()
}

fn random_signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut seed);
    SigningKey::from_bytes(&seed)
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(anyhow!("odd hex length"));
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    for i in (0..b.len()).step_by(2) {
        out.push((hex_val(b[i])? << 4) | hex_val(b[i + 1])?);
    }
    Ok(out)
}

fn hex_val(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(anyhow!("invalid hex char")),
    }
}

/// 连接状态机。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    /// 已发出邀请，等对方首条消息（只有 owner 会停在这里）。
    Invited,
    /// 已接受邀请并建好自己的队列，等对方确认。
    Joining,
    /// 已建立，可以双向收发。
    Established,
    /// 已关闭。
    Closed,
}

/// 出站队列：对方的入站队列地址，以及写它需要的 sender 私钥。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OutQueue {
    pub mailbox: String,
    pub queue_id: [u8; 16],
    pub sender_sk: [u8; 32],
}

/// 首条消息里携带的「我的入站队列」信息（E2E 加密后传输）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LinkOpening {
    pub mailbox: String,
    pub queue_id: [u8; 16],
    pub sender_sk: [u8; 32],
}

/// 一条连接：邀请 + 本端入站队列钥匙 + 出站队列 + E2E 会话。
pub struct Link {
    pub invite: Invite,
    /// 本端入站队列的 owner 钥匙（读/删用）。
    pub owner_keys: QueueKeys,
    /// 本端入站队列地址（= 邀请里的那一条）。
    pub in_queue: [u8; 16],
    pub in_mailbox: String,
    /// 对方的入站队列（拿到 opening 后才有）。
    pub out: Option<OutQueue>,
    pub e2e: crate::layers::crypto::connection::Connection,
    pub state: LinkState,
}

impl Link {
    /// 邀请创建方：生成队列 id、队列钥匙和连接密钥，返回 `(连接, 邀请)`。
    pub fn owner(mailbox: &str) -> (Self, Invite) {
        let (e2e, ek_pub) = crate::layers::crypto::connection::Connection::owner();
        let keys = QueueKeys::generate();
        let mut queue_id = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut queue_id);

        let invite = Invite {
            mailbox: mailbox.to_string(),
            queue_id,
            owner_ek: ek_pub,
            // 邀请即写权限：私钥交给拿到邀请的人。
            sender_sk: keys.sender.to_bytes(),
            ticket: None,
        };
        (
            Self {
                invite: invite.clone(),
                owner_keys: keys,
                in_queue: queue_id,
                in_mailbox: mailbox.to_string(),
                out: None,
                e2e,
                state: LinkState::Invited,
            },
            invite,
        )
    }

    /// 邀请接受方：派生 E2E 会话，生成自己的入站队列，
    /// 出站队列直接取邀请里的那一条。
    pub fn joiner(invite: &Invite) -> anyhow::Result<Self> {
        let e2e = crate::layers::crypto::connection::Connection::joiner(&invite.owner_ek)?;
        let keys = QueueKeys::generate();
        let mut queue_id = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut queue_id);
        Ok(Self {
            invite: invite.clone(),
            owner_keys: keys,
            in_queue: queue_id,
            in_mailbox: String::new(),
            out: Some(OutQueue {
                mailbox: invite.mailbox.clone(),
                queue_id: invite.queue_id,
                sender_sk: invite.sender_sk,
            }),
            e2e,
            state: LinkState::Joining,
        })
    }

    /// 首条消息的明文：告诉对方「往哪条队列写、用什么 key」。
    pub fn opening(&self, mailbox: &str) -> anyhow::Result<Vec<u8>> {
        Ok(serde_json::to_vec(&LinkOpening {
            mailbox: mailbox.to_string(),
            queue_id: self.in_queue,
            sender_sk: self.owner_keys.sender.to_bytes(),
        })?)
    }

    /// owner 解出首条消息后登记对方的队列并转 established。
    pub fn absorb_opening(&mut self, plain: &[u8]) -> anyhow::Result<()> {
        let opening: LinkOpening = serde_json::from_slice(plain)?;
        self.out = Some(OutQueue {
            mailbox: opening.mailbox,
            queue_id: opening.queue_id,
            sender_sk: opening.sender_sk,
        });
        self.state = LinkState::Established;
        Ok(())
    }

    /// 出站队列（还没拿到对方队列时报错）。
    pub fn out_queue(&self) -> anyhow::Result<&OutQueue> {
        self.out
            .as_ref()
            .ok_or_else(|| anyhow!("peer queue not known yet"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Invite {
        Invite {
            mailbox: hex_encode(&[7u8; 32]),
            queue_id: [1u8; 16],
            owner_ek: [2u8; 32],
            sender_sk: [3u8; 32],
            ticket: None,
        }
    }

    #[test]
    fn invite_roundtrip_and_length() {
        let inv = sample();
        let text = inv.encode();
        assert!(text.len() < 200, "invite too long: {}", text.len());
        assert_eq!(Invite::decode(&text).unwrap(), inv);
    }

    #[test]
    fn invite_with_ticket_roundtrip() {
        let mut inv = sample();
        inv.ticket = Some("ticket-abc".into());
        assert_eq!(Invite::decode(&inv.encode()).unwrap(), inv);
    }

    #[test]
    fn reject_bad_prefix_and_truncation() {
        assert!(Invite::decode("nope").is_err());
        let text = sample().encode();
        let cut = &text[..text.len() - 4];
        assert!(Invite::decode(cut).is_err());
    }

    #[test]
    fn link_handshake_and_opening() {
        let (mut owner, invite) = Link::owner(&sample().mailbox);
        assert_eq!(owner.state, LinkState::Invited);
        assert!(!owner.e2e.is_established());

        let mut joiner = Link::joiner(&invite).unwrap();
        assert_eq!(joiner.state, LinkState::Joining);
        assert!(joiner.e2e.is_established());
        assert!(joiner.out_queue().is_ok());

        // 首条消息 = E2E 加密的 opening。
        let opening = joiner.opening("bob-mailbox").unwrap();
        let first = joiner.e2e.encrypt(&opening).unwrap();
        let plain = owner.e2e.decrypt(&first).unwrap();
        owner.absorb_opening(&plain).unwrap();
        assert_eq!(owner.state, LinkState::Established);
        assert_eq!(owner.out_queue().unwrap().mailbox, "bob-mailbox");
        assert_eq!(owner.e2e.session_id(), joiner.e2e.session_id());

        // owner 用对方的 sender 私钥签名才能写对方的队列。
        let out = owner.out_queue().unwrap().clone();
        let sig = sign_send(
            &out.queue_id,
            b"reply",
            &SigningKey::from_bytes(&out.sender_sk),
        );
        let sender_pub: [u8; 32] = *SigningKey::from_bytes(&out.sender_sk)
            .verifying_key()
            .as_bytes();
        assert!(verify(
            &sender_pub,
            DOMAIN_SEND,
            &out.queue_id,
            Some(b"reply"),
            &sig
        ));
    }

    #[test]
    fn state_serialization_roundtrip() {
        let (mut owner, invite) = Link::owner(&sample().mailbox);
        let mut joiner = Link::joiner(&invite).unwrap();
        let first = joiner.e2e.encrypt(&joiner.opening("bob").unwrap()).unwrap();
        let plain = owner.e2e.decrypt(&first).unwrap();
        owner.absorb_opening(&plain).unwrap();

        let mut owner2 =
            crate::layers::crypto::connection::Connection::from_bytes(&owner.e2e.to_bytes())
                .unwrap();
        let mut joiner2 =
            crate::layers::crypto::connection::Connection::from_bytes(&joiner.e2e.to_bytes())
                .unwrap();

        let reply = owner2.encrypt(b"after restart").unwrap();
        assert_eq!(joiner2.decrypt(&reply).unwrap(), b"after restart");
        let back = joiner2.encrypt(b"me too").unwrap();
        assert_eq!(owner2.decrypt(&back).unwrap(), b"me too");
    }

    #[test]
    fn queue_signatures_verify() {
        let keys = QueueKeys::generate();
        let qid = [9u8; 16];
        let payload = b"hello";

        let sig = sign_send(&qid, payload, &keys.sender);
        let sender_pub: [u8; 32] = *keys.sender.verifying_key().as_bytes();
        assert!(verify(&sender_pub, DOMAIN_SEND, &qid, Some(payload), &sig));

        // 换了 payload 就验不过。
        assert!(!verify(
            &sender_pub,
            DOMAIN_SEND,
            &qid,
            Some(b"other"),
            &sig
        ));

        // get 用 owner key。
        let get_sig = sign_get(&qid, &keys.owner);
        let owner_pub: [u8; 32] = *keys.owner.verifying_key().as_bytes();
        assert!(verify(&owner_pub, DOMAIN_GET, &qid, None, &get_sig));
        assert!(!verify(&sender_pub, DOMAIN_GET, &qid, None, &get_sig));
    }
}
