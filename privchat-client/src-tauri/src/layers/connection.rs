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

pub use super::crypto::hex::{hex_decode, hex_encode};

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
    pub ek: [u8; 32],
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
    ///
    /// `mailbox` 既可以是 64 位 hex 的 peer_id，也可以是一整张 EndpointTicket
    /// （无 DNS 环境）；用 1 字节 tag 区分。
    pub fn encode(&self) -> String {
        let mut body = Vec::with_capacity(200);
        body.extend_from_slice(&self.queue_id);
        body.extend_from_slice(&self.ek);
        body.extend_from_slice(&self.sender_sk);
        match hex_decode(&self.mailbox) {
            Ok(bytes) if bytes.len() == 32 => {
                body.push(0);
                body.extend_from_slice(&bytes);
            }
            _ => {
                body.push(1);
                let raw = self.mailbox.as_bytes();
                body.extend_from_slice(&(raw.len() as u16).to_be_bytes());
                body.extend_from_slice(raw);
            }
        }
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
        if bytes.len() < 81 + 1 {
            return Err(anyhow!("invite too short: {}", bytes.len()));
        }
        let queue_id: [u8; 16] = bytes[..16].try_into().unwrap();
        let ek: [u8; 32] = bytes[16..48].try_into().unwrap();
        let sender_sk: [u8; 32] = bytes[48..80].try_into().unwrap();
        let mut pos = 80;
        let tag = bytes[pos];
        pos += 1;
        let mailbox = match tag {
            0 => {
                let raw = bytes
                    .get(pos..pos + 32)
                    .ok_or_else(|| anyhow!("truncated mailbox id"))?;
                pos += 32;
                hex_encode(raw)
            }
            1 => {
                let len = u16::from_be_bytes([
                    *bytes.get(pos).ok_or_else(|| anyhow!("truncated mailbox"))?,
                    *bytes
                        .get(pos + 1)
                        .ok_or_else(|| anyhow!("truncated mailbox"))?,
                ]) as usize;
                pos += 2;
                let raw = bytes
                    .get(pos..pos + len)
                    .ok_or_else(|| anyhow!("truncated mailbox"))?;
                pos += len;
                String::from_utf8(raw.to_vec()).map_err(|_| anyhow!("mailbox not utf8"))?
            }
            _ => return Err(anyhow!("bad mailbox tag")),
        };
        if bytes.len() < pos + 2 {
            return Err(anyhow!("truncated ticket length"));
        }
        let ticket_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        pos += 2;
        if bytes.len() != pos + ticket_len {
            return Err(anyhow!("invite ticket length mismatch"));
        }
        let ticket = if ticket_len == 0 {
            None
        } else {
            Some(
                String::from_utf8(bytes[pos..].to_vec())
                    .map_err(|_| anyhow!("invite ticket is not utf8"))?,
            )
        };
        Ok(Self {
            mailbox,
            queue_id,
            ek,
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

/// 轮换出去的旧入站队列：再轮询几次确认排空后删除。
pub struct DrainingQueue {
    pub mailbox: String,
    pub queue_id: [u8; 16],
    pub keys: QueueKeys,
    /// 剩余轮询次数；到 0 就删除。
    pub polls_left: u32,
}

/// 连接状态机。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    /// 只生成了自己的邀请，还没拿到对方的（等互扫）。
    Pending,
    /// 已配对，双向可发。
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

/// 一条连接：本端入站队列 + 对方入站队列 + E2E 会话。
pub struct Link {
    /// 本端入站队列地址与钥匙（读/删用 owner；sender 私钥发给对方）。
    pub in_queue: [u8; 16],
    pub in_mailbox: String,
    pub owner_keys: QueueKeys,
    /// 对方的入站队列（互扫后才有）。
    pub out: Option<OutQueue>,
    pub e2e: crate::layers::crypto::connection::Connection,
    pub state: LinkState,
    /// 本轮已发多少条；到阈值换队列。
    pub sent_since_rotate: u32,
    /// 手动触发轮换的标记。
    pub user_rotate: bool,
    /// 轮换后待排空的旧入站队列。
    pub draining: Vec<DrainingQueue>,
    /// 创建时间（毫秒）：用来在启动清理时分辨哪条待配对连接更新。
    pub created: u64,
}

impl Link {
    /// 生成本端的入站队列与连接密钥，返回 `(连接, 自己的邀请)`。
    pub fn create(mailbox: &str) -> (Self, Invite) {
        let (e2e, ek_pub) = crate::layers::crypto::connection::Connection::unpaired();
        let keys = QueueKeys::generate();
        let mut queue_id = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut queue_id);

        let invite = Invite {
            mailbox: mailbox.to_string(),
            queue_id,
            ek: ek_pub,
            // 邀请即写权限：私钥交给拿到邀请的人。
            sender_sk: keys.sender.to_bytes(),
            ticket: None,
        };
        (
            Self {
                in_queue: queue_id,
                in_mailbox: mailbox.to_string(),
                owner_keys: keys,
                out: None,
                e2e,
                state: LinkState::Pending,
                sent_since_rotate: 0,
                user_rotate: false,
                draining: Vec::new(),
                created: now_ms(),
            },
            invite,
        )
    }

    /// 互扫到对方邀请后配对：派生 E2E 会话并登记对方队列。
    /// 重新生成自己的邀请：等对方来扫时用（队列和密钥都没变）。
    pub fn invite(&self) -> Invite {
        Invite {
            mailbox: self.in_mailbox.clone(),
            queue_id: self.in_queue,
            ek: self.e2e.own_ek_pub(),
            sender_sk: self.owner_keys.sender.to_bytes(),
            ticket: None,
        }
    }

    pub fn accept(&mut self, their: &Invite) -> anyhow::Result<()> {
        self.e2e.pair_with(&their.ek)?;
        self.out = Some(OutQueue {
            mailbox: their.mailbox.clone(),
            queue_id: their.queue_id,
            sender_sk: their.sender_sk,
        });
        self.state = LinkState::Established;
        Ok(())
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Invite {
        Invite {
            mailbox: hex_encode(&[7u8; 32]),
            queue_id: [1u8; 16],
            ek: [2u8; 32],
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
    fn mutual_scan_pairing() {
        let (mut alice, alice_invite) = Link::create("mb-alice");
        let (mut bob, bob_invite) = Link::create("mb-bob");
        assert_eq!(alice.state, LinkState::Pending);
        assert_eq!(bob.state, LinkState::Pending);
        assert!(!alice.e2e.is_established());

        // 互扫：各自拿到对方的邀请。
        alice.accept(&bob_invite).unwrap();
        bob.accept(&alice_invite).unwrap();
        assert_eq!(alice.state, LinkState::Established);
        assert_eq!(bob.state, LinkState::Established);
        assert_eq!(alice.e2e.session_id(), bob.e2e.session_id());

        // 双方立刻都能发，不需要首条握手消息。
        let m1 = alice.e2e.encrypt(b"from alice").unwrap();
        assert_eq!(bob.e2e.decrypt(&m1).unwrap(), b"from alice");
        let m2 = bob.e2e.encrypt(b"from bob").unwrap();
        assert_eq!(alice.e2e.decrypt(&m2).unwrap(), b"from bob");

        // 出站队列 = 对方的入站队列。
        assert_eq!(alice.out.as_ref().unwrap().queue_id, bob_invite.queue_id);
        assert_eq!(bob.out.as_ref().unwrap().queue_id, alice_invite.queue_id);
    }

    #[test]
    fn state_serialization_roundtrip() {
        let (mut alice, alice_invite) = Link::create("mb-a");
        let (mut bob, bob_invite) = Link::create("mb-b");
        alice.accept(&bob_invite).unwrap();
        bob.accept(&alice_invite).unwrap();

        let mut a2 =
            crate::layers::crypto::connection::Connection::from_bytes(&alice.e2e.to_bytes())
                .unwrap();
        let mut b2 =
            crate::layers::crypto::connection::Connection::from_bytes(&bob.e2e.to_bytes()).unwrap();

        let m = a2.encrypt(b"after restart").unwrap();
        assert_eq!(b2.decrypt(&m).unwrap(), b"after restart");
        let back = b2.encrypt(b"me too").unwrap();
        assert_eq!(a2.decrypt(&back).unwrap(), b"me too");
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
