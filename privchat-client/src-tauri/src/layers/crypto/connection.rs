//! 连接层会话：每连接一对 X25519 密钥 + 对称棘轮 + 按消息数换钥。
//!
//! 关键点：
//! - **没有长期身份**：root 由双方连接公钥做一次 DH 得到，派生完两条链就丢弃；
//! - **每条消息推进链密钥**（前向保密）；
//! - **每 100 条消息换一次整条链**（后妥协恢复）：由连接公钥较小的一方发起，
//!   新公钥随消息头下发，对方看到 epoch+1 自行派生新链，无需额外控制帧；
//! - 旧 epoch 保留一份宽限状态，换钥瞬间在路上的消息仍能解。
//!
//! 头部：magic(4) | ver(1) | epoch(4) | n(4) | ek(32) | nonce(12)。

use anyhow::{anyhow, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::StaticSecret;

const MAGIC: &[u8; 4] = b"PQC2";
const VERSION: u8 = 2;
/// 头部：magic(4) | ver(1) | epoch(4) | n(4) | ek(32) | nonce(12)。
const HEADER_LEN: usize = 4 + 1 + 4 + 4 + 32 + 12;
/// 允许跳过的最大条数（防 DoS）。
const MAX_SKIP: u32 = 200;
/// 每多少条消息换一次整条链。
pub const REKEY_EVERY: u32 = 100;

const INFO_ROOT: &[u8] = b"privchat/conn/root/v1";
const INFO_J2O: &[u8] = b"privchat/conn/j2o/v1";
const INFO_O2J: &[u8] = b"privchat/conn/o2j/v1";
const INFO_CK: &[u8] = b"privchat/conn/ck/v1";
const INFO_SID: &[u8] = b"privchat/conn/id/v1";
/// 状态序列化版本。
const STATE_VERSION: u8 = 3;

/// 一条连接的 E2E 会话。
#[derive(Clone)]
pub struct Connection {
    /// 是否已完成配对。
    established: bool,
    /// 本端是否负责发起换钥（连接公钥较小的一方）。
    initiator: bool,
    /// 当前链的代号，每次换钥 +1。
    epoch: u32,
    /// 本端当前连接密钥。
    own_ek: [u8; 32],
    own_ek_pub: [u8; 32],
    peer_ek: Option<[u8; 32]>,
    send_ck: [u8; 32],
    recv_ck: [u8; 32],
    send_n: u32,
    recv_n: u32,
    /// 当前 epoch 的乱序池。
    skipped: Vec<(u32, [u8; 32])>,
    /// 上一 epoch 的宽限状态（换钥瞬间在路上的消息）。
    prev: Option<PrevEpoch>,
    sid: String,
}

/// 旧 epoch 的只读宽限状态。
#[derive(Clone)]
struct PrevEpoch {
    epoch: u32,
    send_ck: [u8; 32],
    recv_ck: [u8; 32],
    send_n: u32,
    recv_n: u32,
    skipped: Vec<(u32, [u8; 32])>,
}

/// 解析后的消息头。
#[derive(Clone, Copy)]
struct Header {
    epoch: u32,
    n: u32,
    ek: [u8; 32],
    nonce: [u8; 12],
}

impl Connection {
    /// 生成一对连接密钥，但还不知道对端公钥（等互扫）。
    pub fn unpaired() -> (Self, [u8; 32]) {
        let (ek, ek_pub) = new_ek();
        let conn = Self {
            established: false,
            initiator: false,
            epoch: 0,
            own_ek: ek,
            own_ek_pub: ek_pub,
            peer_ek: None,
            send_ck: [0u8; 32],
            recv_ck: [0u8; 32],
            send_n: 0,
            recv_n: 0,
            skipped: Vec::new(),
            prev: None,
            sid: String::new(),
        };
        (conn, ek_pub)
    }

    /// 拿到对方邀请里的连接公钥后完成配对。
    pub fn pair_with(&mut self, peer_ek_pub: &[u8; 32]) -> Result<()> {
        let root = epoch_root(&dh(&self.own_ek, peer_ek_pub)?, 0);
        let (send_ck, recv_ck) = chains_by_order(&root, &self.own_ek_pub, peer_ek_pub);
        self.peer_ek = Some(*peer_ek_pub);
        self.send_ck = send_ck;
        self.recv_ck = recv_ck;
        self.sid = session_id(&self.own_ek_pub, peer_ek_pub);
        self.established = true;
        // 公钥小的一方负责发起换钥，双方判定一致。
        self.initiator = self.own_ek_pub < *peer_ek_pub;
        // root 只在本次调用里用，函数返回即丢弃。
        Ok(())
    }

    pub fn is_established(&self) -> bool {
        self.established
    }

    pub fn session_id(&self) -> &str {
        &self.sid
    }

    /// 当前链代号（测试与观测用）。
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// 加密一条消息；需要换钥时先换。
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if !self.established {
            return Err(anyhow!("connection not established yet"));
        }
        if self.initiator && self.send_n + self.recv_n >= REKEY_EVERY {
            self.rekey()?;
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
        out.extend_from_slice(&self.epoch.to_le_bytes());
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

    /// 换钥：生成新连接密钥，用当前 epoch 派生新 root，重置两条链。
    ///
    /// 对方收到 epoch+1 的消息时用同样的 DH 自行派生，不需要额外消息。
    fn rekey(&mut self) -> Result<()> {
        let peer = self
            .peer_ek
            .ok_or_else(|| anyhow!("cannot rekey without peer key"))?;
        let (ek, ek_pub) = new_ek();
        let next_epoch = self.epoch + 1;
        let new_root = epoch_root(&dh(&ek, &peer)?, next_epoch);
        let (send_ck, recv_ck) = chains_by_order(&new_root, &ek_pub, &peer);

        // 旧链留作宽限，换钥瞬间在路上的消息还能解。
        self.prev = Some(PrevEpoch {
            epoch: self.epoch,
            send_ck: self.send_ck,
            recv_ck: self.recv_ck,
            send_n: self.send_n,
            recv_n: self.recv_n,
            skipped: std::mem::take(&mut self.skipped),
        });
        self.epoch = next_epoch;
        self.own_ek = ek;
        self.own_ek_pub = ek_pub;
        self.send_ck = send_ck;
        self.recv_ck = recv_ck;
        self.send_n = 0;
        self.recv_n = 0;
        Ok(())
    }

    /// 解密一条消息（失败不改状态）。
    pub fn decrypt(&mut self, blob: &[u8]) -> Result<Vec<u8>> {
        let mut trial = self.clone();
        let plain = trial.decrypt_inner(blob)?;
        *self = trial;
        Ok(plain)
    }

    fn decrypt_inner(&mut self, blob: &[u8]) -> Result<Vec<u8>> {
        let hdr = parse_header(blob)?;

        // 对方换钥：epoch 领先一代，用它的新公钥 + 本端当前密钥派生新链。
        if hdr.epoch == self.epoch + 1 {
            let new_root = epoch_root(&dh(&self.own_ek, &hdr.ek)?, hdr.epoch);
            let (send_ck, recv_ck) = chains_by_order(&new_root, &self.own_ek_pub, &hdr.ek);
            self.prev = Some(PrevEpoch {
                epoch: self.epoch,
                send_ck: self.send_ck,
                recv_ck: self.recv_ck,
                send_n: self.send_n,
                recv_n: self.recv_n,
                skipped: std::mem::take(&mut self.skipped),
            });
            self.epoch = hdr.epoch;
            self.peer_ek = Some(hdr.ek);
            self.send_ck = send_ck;
            self.recv_ck = recv_ck;
            self.send_n = 0;
            self.recv_n = 0;
        }

        // 当前 epoch。
        if hdr.epoch == self.epoch {
            let mk = message_key(
                &mut self.recv_ck,
                &mut self.recv_n,
                &mut self.skipped,
                hdr.n,
            )?;
            return decrypt_with(&mk, &hdr, blob);
        }

        // 上一 epoch 的迟到消息：用宽限状态解。
        if let Some(prev) = self.prev.as_mut() {
            if hdr.epoch == prev.epoch {
                let mk = message_key(
                    &mut prev.recv_ck,
                    &mut prev.recv_n,
                    &mut prev.skipped,
                    hdr.n,
                )?;
                return decrypt_with(&mk, &hdr, blob);
            }
        }
        Err(anyhow!(
            "message epoch {} not available (current {})",
            hdr.epoch,
            self.epoch
        ))
    }

    /// 序列化会话状态（不含 root —— 派生后已丢弃）。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(300);
        out.push(STATE_VERSION);
        out.push(u8::from(self.established));
        out.push(u8::from(self.initiator));
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.own_ek);
        out.extend_from_slice(&self.own_ek_pub);
        match self.peer_ek {
            Some(ek) => {
                out.push(1);
                out.extend_from_slice(&ek);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.send_ck);
        out.extend_from_slice(&self.recv_ck);
        out.extend_from_slice(&self.send_n.to_le_bytes());
        out.extend_from_slice(&self.recv_n.to_le_bytes());
        write_skipped(&mut out, &self.skipped);
        match &self.prev {
            Some(prev) => {
                out.push(1);
                out.extend_from_slice(&prev.epoch.to_le_bytes());
                out.extend_from_slice(&prev.send_ck);
                out.extend_from_slice(&prev.recv_ck);
                out.extend_from_slice(&prev.send_n.to_le_bytes());
                out.extend_from_slice(&prev.recv_n.to_le_bytes());
                write_skipped(&mut out, &prev.skipped);
            }
            None => out.push(0),
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut cur = Cursor { bytes, pos: 0 };
        if cur.u8()? != STATE_VERSION {
            return Err(anyhow!("unsupported connection state version"));
        }
        let established = cur.u8()? == 1;
        let initiator = cur.u8()? == 1;
        let epoch = cur.u32()?;
        let own_ek: [u8; 32] = cur.fixed()?;
        let own_ek_pub: [u8; 32] = cur.fixed()?;
        let peer_ek = if cur.u8()? == 1 {
            Some(cur.fixed()?)
        } else {
            None
        };
        let send_ck: [u8; 32] = cur.fixed()?;
        let recv_ck: [u8; 32] = cur.fixed()?;
        let send_n = cur.u32()?;
        let recv_n = cur.u32()?;
        let skipped = cur.skipped()?;
        let prev = if cur.u8()? == 1 {
            let epoch = cur.u32()?;
            let send_ck: [u8; 32] = cur.fixed()?;
            let recv_ck: [u8; 32] = cur.fixed()?;
            let send_n = cur.u32()?;
            let recv_n = cur.u32()?;
            let skipped = cur.skipped()?;
            Some(PrevEpoch {
                epoch,
                send_ck,
                recv_ck,
                send_n,
                recv_n,
                skipped,
            })
        } else {
            None
        };
        if cur.pos != bytes.len() {
            return Err(anyhow!("trailing bytes in connection state"));
        }
        let sid = peer_ek
            .map(|peer| session_id(&own_ek_pub, &peer))
            .unwrap_or_default();
        Ok(Self {
            established,
            initiator,
            epoch,
            own_ek,
            own_ek_pub,
            peer_ek,
            send_ck,
            recv_ck,
            send_n,
            recv_n,
            skipped,
            prev,
            sid,
        })
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        let end = self.pos + n;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| anyhow!("truncated connection state"))?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }

    fn skipped(&mut self) -> Result<Vec<(u32, [u8; 32])>> {
        let len = self.u32()? as usize;
        if len > MAX_SKIP as usize {
            return Err(anyhow!("skipped pool too large"));
        }
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            let n = self.u32()?;
            out.push((n, self.fixed()?));
        }
        Ok(out)
    }
}

fn write_skipped(out: &mut Vec<u8>, skipped: &[(u32, [u8; 32])]) {
    out.extend_from_slice(&(skipped.len() as u32).to_le_bytes());
    for (n, mk) in skipped {
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(mk);
    }
}

fn parse_header(blob: &[u8]) -> Result<Header> {
    if blob.len() < HEADER_LEN || &blob[..4] != MAGIC {
        return Err(anyhow!("bad magic or short blob"));
    }
    if blob[4] != VERSION {
        return Err(anyhow!("bad version"));
    }
    let epoch = u32::from_le_bytes(blob[5..9].try_into().unwrap());
    let n = u32::from_le_bytes(blob[9..13].try_into().unwrap());
    let ek: [u8; 32] = blob[13..45].try_into().unwrap();
    let nonce: [u8; 12] = blob[45..57].try_into().unwrap();
    Ok(Header {
        epoch,
        n,
        ek,
        nonce,
    })
}

fn decrypt_with(mk: &[u8; 32], hdr: &Header, blob: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(mk));
    cipher
        .decrypt(
            Nonce::from_slice(&hdr.nonce),
            Payload {
                msg: &blob[HEADER_LEN..],
                aad: &blob[..HEADER_LEN],
            },
        )
        .map_err(|e| anyhow!("decrypt failed: {e}"))
}

/// 取第 `n` 条消息的密钥：推进接收链，跳过的存池。
fn message_key(
    ck: &mut [u8; 32],
    recv_n: &mut u32,
    skipped: &mut Vec<(u32, [u8; 32])>,
    n: u32,
) -> Result<[u8; 32]> {
    if n < *recv_n {
        return skipped
            .iter()
            .position(|(k, _)| *k == n)
            .map(|i| skipped.remove(i).1)
            .ok_or_else(|| anyhow!("message {n} too old / already used"));
    }
    if n - *recv_n > MAX_SKIP {
        return Err(anyhow!("skip window exceeded: {n} vs {}", recv_n));
    }
    let mut chain = *ck;
    let mut found = None;
    for i in *recv_n..=n {
        let (next, mk) = kdf_ck(&chain);
        chain = next;
        if i == n {
            found = Some(mk);
        } else {
            skipped.push((i, mk));
        }
    }
    *ck = chain;
    *recv_n = n + 1;
    found.ok_or_else(|| anyhow!("key schedule error"))
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

/// 按 epoch 绑定派生：同一对密钥在不同 epoch 得到不同 root。
fn epoch_root(shared: &[u8; 32], epoch: u32) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(shared), &epoch.to_le_bytes());
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

        let m1 = a.encrypt(b"hello").unwrap();
        assert_eq!(b.decrypt(&m1).unwrap(), b"hello");
        let m2 = b.encrypt(b"hi back").unwrap();
        assert_eq!(a.decrypt(&m2).unwrap(), b"hi back");
    }

    #[test]
    fn tamper_and_replay_rejected() {
        let (mut a, mut b) = pair();
        let m = a.encrypt(b"one").unwrap();
        let mut bad = m.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(b.decrypt(&bad).is_err());
        assert_eq!(b.decrypt(&m).unwrap(), b"one");
        assert!(b.decrypt(&m).is_err(), "replay must fail");
    }

    #[test]
    fn out_of_order_within_window() {
        let (mut a, mut b) = pair();
        let m1 = a.encrypt(b"m1").unwrap();
        let m2 = a.encrypt(b"m2").unwrap();
        assert_eq!(b.decrypt(&m2).unwrap(), b"m2");
        assert_eq!(b.decrypt(&m1).unwrap(), b"m1");
    }

    #[test]
    fn third_party_cannot_open() {
        let (_a, mut b) = pair();
        let (mut other, _p) = Connection::unpaired();
        let _ = other;
        let m = {
            let (mut a, _p2) = Connection::unpaired();
            let (mut x, xp) = Connection::unpaired();
            let (mut y, yp) = Connection::unpaired();
            a.pair_with(&yp).unwrap();
            x.pair_with(&_p2).unwrap();
            let _ = y;
            let _ = b;
            a.encrypt(b"secret").unwrap()
        };
        assert!(b.decrypt(&m).is_err());
    }

    #[test]
    fn rekey_every_100_messages_is_seamless() {
        let (mut a, mut b) = pair();
        assert_ne!(a.initiator, b.initiator, "roles must be complementary");
        let a_is_init = a.initiator;

        // 交错收发 160 条；发起方计数到 100 时会换钥。
        for i in 0..160 {
            let a_sends = (i % 2 == 0) == a_is_init;
            if a_sends {
                let m = a.encrypt(format!("a{i}").as_bytes()).unwrap();
                assert_eq!(b.decrypt(&m).unwrap(), format!("a{i}").as_bytes());
            } else {
                let m = b.encrypt(format!("b{i}").as_bytes()).unwrap();
                assert_eq!(a.decrypt(&m).unwrap(), format!("b{i}").as_bytes());
            }
        }
        assert_eq!(a.epoch, b.epoch, "both sides must agree on epoch");
        assert!(
            a.epoch >= 1,
            "expected at least one rekey, epoch {}",
            a.epoch
        );

        // 换钥后双向继续可用。
        let m = b.encrypt(b"after rekey").unwrap();
        assert_eq!(a.decrypt(&m).unwrap(), b"after rekey");
        let m = a.encrypt(b"and back").unwrap();
        assert_eq!(b.decrypt(&m).unwrap(), b"and back");
    }

    #[test]
    fn old_epoch_message_still_decrypts_after_rekey() {
        let (mut a, mut b) = pair();
        let a_is_init = a.initiator;
        // 让发起方先发一条旧 epoch 的消息，但暂不投递。
        let stale = if a_is_init {
            a.encrypt(b"stale").unwrap()
        } else {
            b.encrypt(b"stale").unwrap()
        };
        // 发起方再发 120 条，触发换钥。
        for i in 0..120 {
            let m = if a_is_init {
                a.encrypt(format!("n{i}").as_bytes()).unwrap()
            } else {
                b.encrypt(format!("n{i}").as_bytes()).unwrap()
            };
            let _ = if a_is_init {
                b.decrypt(&m).unwrap()
            } else {
                a.decrypt(&m).unwrap()
            };
        }
        // 迟到的旧 epoch 消息仍能用宽限状态解开。
        let got = if a_is_init {
            b.decrypt(&stale).unwrap()
        } else {
            a.decrypt(&stale).unwrap()
        };
        assert_eq!(got, b"stale");
    }

    #[test]
    fn state_serialization_roundtrip() {
        let (mut a, mut b) = pair();
        let m = a.encrypt(b"x").unwrap();
        assert_eq!(b.decrypt(&m).unwrap(), b"x");

        let mut a2 = Connection::from_bytes(&a.to_bytes()).unwrap();
        let mut b2 = Connection::from_bytes(&b.to_bytes()).unwrap();
        let m = a2.encrypt(b"after restart").unwrap();
        assert_eq!(b2.decrypt(&m).unwrap(), b"after restart");
        let back = b2.encrypt(b"me too").unwrap();
        assert_eq!(a2.decrypt(&back).unwrap(), b"me too");
    }
}
