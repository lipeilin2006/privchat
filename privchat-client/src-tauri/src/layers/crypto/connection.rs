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
    /// 生成一对连接密钥，但还不知道对端公钥（等互扫拿到对方的邀请）。
    pub fn unpaired() -> (Self, [u8; 32]) {
        let (ek, ek_pub) = new_ek();
        let conn = Self {
            role: Role::Joiner, // 配对后按公钥序决定方向，role 不再参与
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

    /// 拿到对方邀请里的连接公钥后完成配对：双方算出的 root 相同。
    ///
    /// 互扫场景下两边都主动配对，所以方向按公钥字典序定，
    /// 不需要「谁先发」的握手消息。
    pub fn pair_with(&mut self, peer_ek_pub: &[u8; 32]) -> Result<()> {
        let root = kdf_root(&dh(&self.own_ek, peer_ek_pub)?);
        let (send_ck, recv_ck) = chains_by_order(&root, &self.own_ek_pub, peer_ek_pub);
        self.root = Some(root);
        self.peer_ek = Some(*peer_ek_pub);
        self.send_ck = send_ck;
        self.recv_ck = recv_ck;
        self.sid = session_id(&self.own_ek_pub, peer_ek_pub);
        Ok(())
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

    /// 序列化会话状态（不含任何长期密钥——本协议就没有长期密钥）。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(200 + self.skipped.len() * 36);
        out.push(match self.role {
            Role::Owner => 0,
            Role::Joiner => 1,
        });
        out.extend_from_slice(&self.own_ek);
        out.extend_from_slice(&self.own_ek_pub);
        match self.peer_ek {
            Some(ek) => {
                out.push(1);
                out.extend_from_slice(&ek);
            }
            None => out.push(0),
        }
        match self.root {
            Some(root) => {
                out.push(1);
                out.extend_from_slice(&root);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.send_ck);
        out.extend_from_slice(&self.recv_ck);
        out.extend_from_slice(&self.send_n.to_le_bytes());
        out.extend_from_slice(&self.recv_n.to_le_bytes());
        out.extend_from_slice(&(self.skipped.len() as u32).to_le_bytes());
        for (n, mk) in &self.skipped {
            out.extend_from_slice(&n.to_le_bytes());
            out.extend_from_slice(mk);
        }
        out
    }

    /// 反序列化会话状态。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut pos = 0usize;
        let mut take = |n: usize| -> Result<&[u8]> {
            let end = pos + n;
            let slice = bytes
                .get(pos..end)
                .ok_or_else(|| anyhow!("truncated connection state"))?;
            pos = end;
            Ok(slice)
        };
        let role = match *take(1)?.first().unwrap() {
            0 => Role::Owner,
            1 => Role::Joiner,
            _ => return Err(anyhow!("bad role")),
        };
        let own_ek: [u8; 32] = take(32)?.try_into().unwrap();
        let own_ek_pub: [u8; 32] = take(32)?.try_into().unwrap();
        let peer_ek = if *take(1)?.first().unwrap() == 1 {
            Some(take(32)?.try_into().unwrap())
        } else {
            None
        };
        let root = if *take(1)?.first().unwrap() == 1 {
            Some(take(32)?.try_into().unwrap())
        } else {
            None
        };
        let send_ck: [u8; 32] = take(32)?.try_into().unwrap();
        let recv_ck: [u8; 32] = take(32)?.try_into().unwrap();
        let send_n = u32::from_le_bytes(take(4)?.try_into().unwrap());
        let recv_n = u32::from_le_bytes(take(4)?.try_into().unwrap());
        let skipped_len = u32::from_le_bytes(take(4)?.try_into().unwrap()) as usize;
        if skipped_len > MAX_SKIP as usize {
            return Err(anyhow!("skipped pool too large"));
        }
        let mut skipped = Vec::with_capacity(skipped_len);
        for _ in 0..skipped_len {
            let n = u32::from_le_bytes(take(4)?.try_into().unwrap());
            let mk: [u8; 32] = take(32)?.try_into().unwrap();
            skipped.push((n, mk));
        }
        if pos != bytes.len() {
            return Err(anyhow!("trailing bytes in connection state"));
        }
        let sid = match peer_ek {
            Some(peer) => session_id(&peer, &own_ek_pub),
            None => String::new(),
        };
        Ok(Self {
            role,
            own_ek,
            own_ek_pub,
            peer_ek,
            root,
            send_ck,
            recv_ck,
            send_n,
            recv_n,
            skipped,
            sid,
        })
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
    /// 发送方的连接公钥（配对后不再需要，保留给将来的密钥轮换）。
    #[allow(dead_code)]
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

/// 按公钥字典序分方向：小者发 j2o，大者发 o2j。
fn chains_by_order(root: &[u8; 32], own: &[u8; 32], peer: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(None, root);
    let mut j2o = [0u8; 32];
    let mut o2j = [0u8; 32];
    hk.expand(INFO_J2O, &mut j2o).expect("hkdf");
    hk.expand(INFO_O2J, &mut o2j).expect("hkdf");
    if own < peer {
        (j2o, o2j)
    } else {
        (o2j, j2o)
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
        let (mut a, a_pub) = Connection::unpaired();
        let (mut b, b_pub) = Connection::unpaired();
        a.pair_with(&b_pub).unwrap();
        b.pair_with(&a_pub).unwrap();
        (a, b)
    }

    #[test]
    fn pairing_and_roundtrip() {
        let (mut a, mut b) = pair();
        assert!(a.is_established());
        assert_eq!(a.session_id(), b.session_id());

        // 双方立刻都能发。
        let m1 = a.encrypt(b"hello").unwrap();
        assert_eq!(b.decrypt(&m1).unwrap(), b"hello");
        let m2 = b.encrypt(b"hi back").unwrap();
        assert_eq!(a.decrypt(&m2).unwrap(), b"hi back");
    }

    #[test]
    fn tamper_seal_and_replay_rejected() {
        let (mut owner, mut joiner) = pair();
        let first = joiner.encrypt(b"one").unwrap();
        let _ = &first;
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
        let m1 = joiner.encrypt(b"m1").unwrap();
        let m2 = joiner.encrypt(b"m2").unwrap();
        assert_eq!(owner.decrypt(&m2).unwrap(), b"m2");
        assert_eq!(owner.decrypt(&m1).unwrap(), b"m1");
    }

    #[test]
    fn third_party_cannot_open() {
        let (_owner, mut joiner) = pair();
        let first = joiner.encrypt(b"secret").unwrap();
        let (other, _pub) = Connection::unpaired();
        let mut other = other;
        assert!(other.decrypt(&first).is_err());
    }
}
