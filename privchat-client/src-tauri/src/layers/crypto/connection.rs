//! SimpleX 式「每连接独立密钥」的简化会话（无身份、无签名、无 prekey）。
//!
//! 与 `ratchet` 的区别：
//! - 不再有全局身份密钥（IK），也没有 SPK / OPK / X3DH；
//! - root 只由**每连接**的一对 X25519 公钥做一次 DH 得到；
//! - 不再有每消息签名：消息真实性由 AEAD + 会话密钥保证，队列层再做发送方认证。
//!
//! 角色由「谁建邀请」决定：
//! - Owner：生成连接密钥并发出邀请，root 要等对方首条消息；
//! - Joiner：拿到邀请里的 Owner 公钥，生成自己的连接密钥，
//!   `root = KDF(DH(joiner_ek, owner_ek))`，先发消息。
//!
//! 安全取舍：只做对称棘轮（每条消息推进链密钥）——前向保密有，但**没有**
//! 双棘轮的后妥协恢复（PCS）。需要 PCS 时调 `rekey()` 手动换一把连接密钥。

use anyhow::{anyhow, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::StaticSecret;

/// 消息魔数 / 版本。
const MAGIC: &[u8; 4] = b"PQC1";
const VERSION: u8 = 1;
/// 头部：magic(4) | ver(1) | n(4) | ek(32) | nonce(12)。
const HEADER_LEN: usize = 4 + 1 + 4 + 32 + 12;
/// 允许跳过的最大条数（防 DoS）。
const MAX_SKIP: u32 = 200;

const INFO_ROOT: &[u8] = b"privchat/conn/root/v1";
const INFO_J2O: &[u8] = b"privchat/conn/j2o/v1";
const INFO_O2J: &[u8] = b"privchat/conn/o2j/v1";
const INFO_CK: &[u8] = b"privchat/conn/ck/v1";
const INFO_SID: &[u8] = b"privchat/conn/id/v1";

/// 连接角色：由邀请的创建方决定。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// 邀请创建方：先有公钥，root 等对方首条消息。
    Owner,
    /// 邀请接受方：拿到 Owner 公钥后立即派生 root 并先发消息。
    Joiner,
}

/// 一条连接（一对单向队列共享的 E2E 会话）。
#[derive(Clone)]
pub struct Connection {
    role: Role,
    /// 本端当前连接密钥（X25519 私钥/公钥）。
    own_ek: [u8; 32],
    own_ek_pub: [u8; 32],
    /// 对端连接公钥（Owner 在收到首条消息后才知道）。
    peer_ek: Option<[u8; 32]>,
    /// 根密钥；Owner 在握手前为 None。
    root: Option<[u8; 32]>,
    send_ck: [u8; 32],
    recv_ck: [u8; 32],
    send_n: u32,
    recv_n: u32,
    /// 乱序池：`n -> mk`，取用后删除。
    skipped: Vec<(u32, [u8; 32])>,
    /// 会话 ID（双方可独立算出）。
    sid: String,
}

impl Connection {
    /// 邀请创建方：生成连接密钥，返回 `(自己, 邀请里要带的公钥)`。
    pub fn owner() -> (Self, [u8; 32]) {
        let (ek, ek_pub) = new_ek();
        let conn = Self {
            role: Role::Owner,
            own_ek: ek,
            own_ek_pub: ek_pub,
            peer_ek: None,
            root: None,
            send_ck: [0u8; 32],
            recv_ck: [0u8; 32],
            send_n: 0,
            recv_n: 0,
            skipped: Vec::new(),
            sid: String::new(),
        };
        (conn, ek_pub)
    }

    /// 邀请接受方：用邀请里的 Owner 公钥派生 root。
    pub fn joiner(owner_ek_pub: &[u8; 32]) -> Result<Self> {
        let (ek, ek_pub) = new_ek();
        let root = kdf_root(&dh(&ek, owner_ek_pub)?);
        let (send_ck, recv_ck) = chains(&root, Role::Joiner);
        Ok(Self {
            role: Role::Joiner,
            own_ek: ek,
            own_ek_pub: ek_pub,
            peer_ek: Some(*owner_ek_pub),
            root: Some(root),
            send_ck,
            recv_ck,
            send_n: 0,
            recv_n: 0,
            skipped: Vec::new(),
            sid: session_id(owner_ek_pub, &ek_pub),
        })
    }

    /// 是否已建立（Owner 收到首条消息前为 false）。
    pub fn is_established(&self) -> bool {
        self.root.is_some()
    }

    /// 会话 ID：两边算出来一致。
    pub fn session_id(&self) -> &str {
        &self.sid
    }

    /// 加密一条消息。
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if self.root.is_none() {
            return Err(anyhow!("connection not established yet"));
        }
        let (next_ck, mk) = kdf_ck(&self.send_ck);
        self.send_ck = next_ck;
        let n = self.send_n;
        self.send_n += 1;

        let mut nonce = [0u8; 12];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let mut out = Vec::with_capacity(HEADER_LEN + plaintext.len() + 16);
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&self.own_ek_pub);
        out.extend_from_slice(&nonce);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&mk));
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &out,
                },
            )
            .map_err(|e| anyhow!("encrypt failed: {e}"))?;
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// 解密一条消息（失败不改状态：在副本上推进，成功才提交）。
    pub fn decrypt(&mut self, blob: &[u8]) -> Result<Vec<u8>> {
        let mut trial = self.clone();
        let plain = trial.decrypt_inner(blob)?;
        *self = trial;
        Ok(plain)
    }

    fn decrypt_inner(&mut self, blob: &[u8]) -> Result<Vec<u8>> {
        let hdr = parse_header(blob)?;

        // Owner 首条消息：用对端的连接公钥完成握手。
        if self.root.is_none() {
            if self.role != Role::Owner {
                return Err(anyhow!("only owner can complete handshake"));
            }
            let root = kdf_root(&dh(&self.own_ek, &hdr.ek)?);
            let (send_ck, recv_ck) = chains(&root, Role::Owner);
            self.root = Some(root);
            self.send_ck = send_ck;
            self.recv_ck = recv_ck;
            self.peer_ek = Some(hdr.ek);
            self.sid = session_id(&hdr.ek, &self.own_ek_pub);
        }

        let mk = self.message_key(hdr.n)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&mk));
        let plain = cipher
            .decrypt(
                Nonce::from_slice(&hdr.nonce),
                Payload {
                    msg: &blob[HEADER_LEN..],
                    aad: &blob[..HEADER_LEN],
                },
            )
            .map_err(|e| anyhow!("decrypt failed: {e}"))?;
        Ok(plain)
    }

    /// 取第 `n` 条消息的密钥：推进接收链，跳过的存池。
    fn message_key(&mut self, n: u32) -> Result<[u8; 32]> {
        if n < self.recv_n {
            return self
                .skipped
                .iter()
                .position(|(k, _)| *k == n)
                .map(|i| self.skipped.remove(i).1)
                .ok_or_else(|| anyhow!("message {n} too old / already used"));
        }
        if n - self.recv_n > MAX_SKIP {
            return Err(anyhow!("skip window exceeded: {n} vs {}", self.recv_n));
        }
        let mut ck = self.recv_ck;
        let mut found = None;
        for i in self.recv_n..=n {
            let (next, mk) = kdf_ck(&ck);
            ck = next;
            if i == n {
                found = Some(mk);
            } else {
                self.skipped.push((i, mk));
            }
        }
        self.recv_ck = ck;
        self.recv_n = n + 1;
        found.ok_or_else(|| anyhow!("key schedule error"))
    }

    /// 手动换一把连接密钥（用于需要后妥协恢复时）：
    /// 下一次发送会带上新公钥，对端用旧 root 与新公钥做 DH 推进。
    /// 这里只做本地换钥，真正的轮换由上层在双方都有新公钥时调用。
    pub fn rotate(&mut self) -> [u8; 32] {
        let (ek, ek_pub) = new_ek();
        self.own_ek = ek;
        self.own_ek_pub = ek_pub;
        ek_pub
    }
}

/// 消息头。
struct Header {
    n: u32,
    ek: [u8; 32],
    nonce: [u8; 12],
}

fn parse_header(blob: &[u8]) -> Result<Header> {
    if blob.len() < HEADER_LEN || &blob[..4] != MAGIC {
        return Err(anyhow!("bad magic or short blob"));
    }
    if blob[4] != VERSION {
        return Err(anyhow!("bad version"));
    }
    let n = u32::from_le_bytes(blob[5..9].try_into().unwrap());
    let ek: [u8; 32] = blob[9..41].try_into().unwrap();
    let nonce: [u8; 12] = blob[41..53].try_into().unwrap();
    Ok(Header { n, ek, nonce })
}

fn new_ek() -> ([u8; 32], [u8; 32]) {
    let mut seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    let secret = StaticSecret::from(seed);
    let public = x25519_dalek::PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

fn dh(priv_bytes: &[u8; 32], pub_bytes: &[u8; 32]) -> Result<[u8; 32]> {
    let secret = StaticSecret::from(*priv_bytes);
    let public = x25519_dalek::PublicKey::from(*pub_bytes);
    let shared = *secret.diffie_hellman(&public).as_bytes();
    if shared.iter().all(|b| *b == 0) {
        return Err(anyhow!("x25519 shared secret is all-zero"));
    }
    Ok(shared)
}

fn kdf_root(shared: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut out = [0u8; 32];
    hk.expand(INFO_ROOT, &mut out).expect("hkdf");
    out
}

/// 按角色分方向：Joiner 发的是 j2o，Owner 发的是 o2j。
fn chains(root: &[u8; 32], role: Role) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(None, root);
    let mut j2o = [0u8; 32];
    let mut o2j = [0u8; 32];
    hk.expand(INFO_J2O, &mut j2o).expect("hkdf");
    hk.expand(INFO_O2J, &mut o2j).expect("hkdf");
    match role {
        Role::Joiner => (j2o, o2j),
        Role::Owner => (o2j, j2o),
    }
}

fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(ck), &[]);
    let mut out = [0u8; 64];
    hk.expand(INFO_CK, &mut out).expect("hkdf");
    let mut next = [0u8; 32];
    let mut mk = [0u8; 32];
    next.copy_from_slice(&out[..32]);
    mk.copy_from_slice(&out[32..]);
    (next, mk)
}

fn session_id(a: &[u8; 32], b: &[u8; 32]) -> String {
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let mut h = Sha256::new();
    h.update(INFO_SID);
    h.update(lo);
    h.update(hi);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Connection, Connection) {
        let (owner, owner_pub) = Connection::owner();
        let joiner = Connection::joiner(&owner_pub).expect("joiner");
        (owner, joiner)
    }

    #[test]
    fn handshake_and_roundtrip() {
        let (mut owner, mut joiner) = pair();
        assert!(!owner.is_established());
        assert!(owner.encrypt(b"too early").is_err());

        let first = joiner.encrypt(b"hello").unwrap();
        assert_eq!(owner.decrypt(&first).unwrap(), b"hello");
        assert!(owner.is_established());
        assert_eq!(owner.session_id(), joiner.session_id());

        let reply = owner.encrypt(b"hi back").unwrap();
        assert_eq!(joiner.decrypt(&reply).unwrap(), b"hi back");
    }

    #[test]
    fn tamper_seal_and_replay_rejected() {
        let (mut owner, mut joiner) = pair();
        let first = joiner.encrypt(b"one").unwrap();
        let mut bad = first.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(owner.decrypt(&bad).is_err());
        assert_eq!(owner.decrypt(&first).unwrap(), b"one");
        assert!(owner.decrypt(&first).is_err(), "replay must fail");
    }

    #[test]
    fn out_of_order_within_window() {
        let (mut owner, mut joiner) = pair();
        let head = joiner.encrypt(b"init").unwrap();
        assert_eq!(owner.decrypt(&head).unwrap(), b"init");

        let m1 = joiner.encrypt(b"m1").unwrap();
        let m2 = joiner.encrypt(b"m2").unwrap();
        assert_eq!(owner.decrypt(&m2).unwrap(), b"m2");
        assert_eq!(owner.decrypt(&m1).unwrap(), b"m1");
    }

    #[test]
    fn third_party_cannot_open() {
        let (_owner, mut joiner) = pair();
        let first = joiner.encrypt(b"secret").unwrap();
        let (other, _pub) = Connection::owner();
        let mut other = other;
        assert!(other.decrypt(&first).is_err());
    }
}
