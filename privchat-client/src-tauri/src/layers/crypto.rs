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
//! [0..4] magic "PRR3" | [4] version=5 | [5..9] gen u32LE
//! [9..41] dh_pub (32) | [41..45] n u32LE | [45..49] pn u32LE
//! [49..81] prev_eph (32) | [81..93] nonce (12) | [93..] ChaCha20-Poly1305 ciphertext
//! ```
//! 固定前缀 93 字节（gen 为 u32，杜绝刷新回绕），完整头作为 AEAD AAD
//! 认证。mailbox 只接触密文。

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use rand_core::RngCore;
use sha2::Sha256;
use x25519_dalek::StaticSecret;

/// wire 消息头魔数。
const MAGIC: &[u8; 4] = b"PRR3";
/// 状态 / 消息版本。
const VERSION: u8 = 5;
/// 消息固定前缀长度。
const HEADER_LEN: usize = 93;
/// 单次前跳 / 跨代快进的最大窗口。
const MAX_SKIP: u32 = 200;
/// skipped 池容量上限（防 DoS）。
const SKIPPED_MAX: usize = 1000;

const INFO_ROOT: &[u8] = b"privchat/ratchet/root/v1";
const INFO_RK: &[u8] = b"privchat/ratchet/rk/v1";
const INFO_CK: &[u8] = b"privchat/ratchet/ck/v1";
const INFO_CHAIN_LOW: &[u8] = b"privchat/ratchet/chain/low";
const INFO_CHAIN_HIGH: &[u8] = b"privchat/ratchet/chain/high";

/// 双棘轮会话。key 为 `(local_id, peer_id)`：本端专属身份 + 对端 peer_id。
pub struct Ratchet {
    /// 本端长期密钥（内存态，不入序列化）。
    own: iroh::SecretKey,
    /// 本端 Ed25519 公钥字节（链方向判定用）。
    own_pub: [u8; 32],
    peer_id: String,
    /// 对端 Ed25519 公钥字节。
    peer_pub: [u8; 32],
    /// 当前根棘轮代（每次收敛刷新 +1，从 0 起）。
    gen: u32,
    /// 当前代根密钥。
    root: [u8; 32],
    /// 本端当前代临时 X25519 密钥对（发送前懒生成）。
    our_eph_priv: Option<[u8; 32]>,
    our_eph_pub: Option<[u8; 32]>,
    /// 对端当前代临时公钥（gen, pub）。
    their_eph: Option<(u32, [u8; 32])>,
    /// 本端刷新上一代所用的旧 eph 公钥（gen g 刷新到 g+1 后固定为本代携带值）。
    /// 随每个消息头冗余携带：接收方收敛刷新时用它替代 `their_eph`，即使漏收
    /// 旧代消息也能还原同一 root。
    prev_eph: [u8; 32],
    /// 发送链 / 发送计数。
    send_ck: [u8; 32],
    send_n: u32,
    /// 接收链 / 接收计数。
    recv_ck: [u8; 32],
    recv_n: u32,
    /// 上一代发送条数：刷新后作为后续消息头 `pn`（接收方据此快进旧链）。
    prev_send_n: u32,
    /// gen0 接收链是否已绑定到对方临时 eph（X3DH 式绑定，只做一次）。
    recv_bound: bool,
    /// 滑动窗口池：`(gen, n) -> 消息密钥`，取用后删除。
    skipped: HashMap<(u32, u32), [u8; 32]>,
    /// 待提交的发送推进：`encrypt` 只在试算副本上推进并暂存于此，
    /// 由上层确认消息送达（`next`）后提交，发送失败则不提交。
    pending: Option<Box<Ratchet>>,
}

/// 解析后的消息头。
struct Header {
    len: usize,
    gen: u32,
    dh_pub: [u8; 32],
    n: u32,
    pn: u32,
    prev_eph: [u8; 32],
    nonce: [u8; 12],
}

impl Ratchet {
    /// 新建（或从零开始）一个与 `peer_id` 的会话。root₀ 由静态 ECDH 派生，
    /// 双方各自计算得到同一值；gen=0 的消息双方均可直接解密。
    pub fn new(own: &iroh::SecretKey, peer_id: &str) -> Result<Self> {
        let peer_pub = decode_peer_pub(peer_id)?;
        let own_pub = own.public().as_bytes().to_owned();
        let root = root0(own, &peer_pub)?;
        let (send_ck, recv_ck) = derive_chains(&root, &own_pub, &peer_pub);
        Ok(Self {
            own: own.clone(),
            own_pub,
            peer_id: peer_id.to_string(),
            peer_pub,
            gen: 0,
            root,
            our_eph_priv: None,
            our_eph_pub: None,
            their_eph: None,
            prev_eph: [0u8; 32],
            send_ck,
            send_n: 0,
            recv_ck,
            recv_n: 0,
            prev_send_n: 0,
            recv_bound: false,
            skipped: HashMap::new(),
            pending: None,
        })
    }

    /// 加密一段明文，返回带头的密文 blob。推进在试算副本上完成后暂存
    /// 于 `pending`，不立即提交：由上层确认消息送达后调用 [`next`] 提交，
    /// 发送失败则不调用（自然回滚，不污染会话链）。
    ///
    /// [`next`]: Ratchet::next
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // 本代 eph 一旦生成就固定下来：失败重试必须复用同一个 eph，否则
        // gen0 的绑定链会在「已送达但未提交」和重试之间漂移，对端解不开。
        if self.our_eph_priv.is_none() {
            let (priv_bytes, pub_bytes) = new_eph();
            self.our_eph_priv = Some(priv_bytes);
            self.our_eph_pub = Some(pub_bytes);
        }
        let mut trial = self.clone();
        let blob = trial.encrypt_inner(plaintext)?;
        self.pending = Some(Box::new(trial));
        Ok(blob)
    }

    /// 提交上一次 [`encrypt`] 的推进。发送成功（含 mailbox 兜底投递）后
    /// 调用；发送失败则不要调用，本会话保持加密前状态。
    ///
    /// 同代只合并发送侧字段（send_ck/send_n/eph），保留期间可能已推进的
    /// 接收侧；跨代（加密触发收敛刷新）则整体切换到新代状态。
    ///
    /// [`encrypt`]: Ratchet::encrypt
    pub fn next(&mut self) {
        let Some(p) = self.pending.take() else { return };
        let p = *p;
        if p.gen > self.gen {
            // 加密时发生了收敛刷新：发送/接收链都切换到新代，整体提交。
            *self = p;
        } else {
            // 同代：只提交发送侧推进，保留本端接收侧（期间可能已解密）。
            self.send_ck = p.send_ck;
            self.send_n = p.send_n;
            self.prev_send_n = p.prev_send_n;
            self.our_eph_priv = p.our_eph_priv;
            self.our_eph_pub = p.our_eph_pub;
        }
    }

    /// 解密一段密文 blob。状态变更在试算副本上完成后提交，失败时
    /// 不推进任何链状态（防污染）。若存在待提交的发送推进（`pending`），
    /// 接收侧先于发送侧推进时会把 pending 的接收侧同步到新状态，避免
    /// `next` 提交时回退期间已收到的消息。
    pub fn decrypt(&mut self, blob: &[u8]) -> Result<Vec<u8>> {
        let mut trial = self.clone();
        let plain = trial.decrypt_inner(blob)?;
        let pending = self.pending.take();
        *self = trial;
        if let Some(mut p) = pending {
            // 接收侧以解密后为准；跨代刷新时发送侧也应随新代重派生，
            // 否则 next 提交会回退。同代时保留 pending 的发送侧推进。
            p.recv_ck = self.recv_ck;
            p.recv_n = self.recv_n;
            p.skipped = self.skipped.clone();
            p.their_eph = self.their_eph;
            if p.gen != self.gen {
                p.send_ck = self.send_ck;
                p.send_n = self.send_n;
                p.prev_send_n = self.prev_send_n;
                p.our_eph_priv = self.our_eph_priv;
                p.our_eph_pub = self.our_eph_pub;
                p.prev_eph = self.prev_eph;
            }
            self.pending = Some(p);
        }
        Ok(plain)
    }

    /// 是否为本层可识别的密文格式（magic + version）。用于 mailbox 轮询
    /// 在不消耗棘轮状态的前提下做格式预检。
    pub fn has_valid_prefix(blob: &[u8]) -> bool {
        parse_header(blob).is_ok()
    }

    /// 读取消息头的 `(gen, n)` —— 发送方的绝对逻辑发送序（Epoch, Seq）。
    /// 明文可读，mailbox 不参与；接收端据 (gen,n) 排序/自校验。
    pub fn header_gen_n(blob: &[u8]) -> Result<(u32, u32)> {
        let hdr = parse_header(blob)?;
        Ok((hdr.gen, hdr.n))
    }

    /// 序列化会话状态（不含长期私钥与对端标识，二者由 DB 键提供）。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(264 + self.skipped.len() * 40);
        out.push(VERSION);
        out.extend_from_slice(&self.gen.to_le_bytes());
        out.extend_from_slice(&self.root);
        let flags =
            u8::from(self.our_eph_priv.is_some()) | (u8::from(self.their_eph.is_some()) << 1);
        out.push(flags);
        if let Some(priv_bytes) = self.our_eph_priv {
            out.extend_from_slice(&priv_bytes);
            out.extend_from_slice(self.our_eph_pub.as_ref().unwrap());
        }
        if let Some((g, pub_bytes)) = self.their_eph {
            out.extend_from_slice(&g.to_le_bytes());
            out.extend_from_slice(&pub_bytes);
        }
        out.extend_from_slice(&self.prev_eph);
        out.extend_from_slice(&self.send_ck);
        out.extend_from_slice(&self.send_n.to_le_bytes());
        out.extend_from_slice(&self.recv_ck);
        out.extend_from_slice(&self.recv_n.to_le_bytes());
        out.extend_from_slice(&self.prev_send_n.to_le_bytes());
        out.push(u8::from(self.recv_bound));
        out.extend_from_slice(&(self.skipped.len() as u32).to_le_bytes());
        for ((g, n), mk) in &self.skipped {
            out.extend_from_slice(&g.to_le_bytes());
            out.extend_from_slice(&n.to_le_bytes());
            out.extend_from_slice(mk);
        }
        out
    }

    /// 反序列化会话状态，续用链状态。own/peer_id 由调用方按 DB 键传入。
    pub fn from_bytes(own: &iroh::SecretKey, peer_id: &str, bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 2 || bytes[0] != VERSION {
            return Err(anyhow!("invalid ratchet state version"));
        }
        let mut pos = 1;
        let gen = read_u32(bytes, &mut pos)?;
        let root = read_fixed::<32>(bytes, &mut pos)?;
        let flags = read_u8(bytes, &mut pos)?;
        let has_eph = flags & 1 == 1;
        let has_their = flags & 2 == 2;
        let (our_eph_priv, our_eph_pub) = if has_eph {
            (
                Some(read_fixed::<32>(bytes, &mut pos)?),
                Some(read_fixed::<32>(bytes, &mut pos)?),
            )
        } else {
            (None, None)
        };
        let their_eph = if has_their {
            let g = read_u32(bytes, &mut pos)?;
            Some((g, read_fixed::<32>(bytes, &mut pos)?))
        } else {
            None
        };
        let prev_eph = read_fixed::<32>(bytes, &mut pos)?;
        let send_ck = read_fixed::<32>(bytes, &mut pos)?;
        let send_n = read_u32(bytes, &mut pos)?;
        let recv_ck = read_fixed::<32>(bytes, &mut pos)?;
        let recv_n = read_u32(bytes, &mut pos)?;
        let prev_send_n = read_u32(bytes, &mut pos)?;
        let recv_bound = read_u8(bytes, &mut pos)? != 0;
        let skipped_count = read_u32(bytes, &mut pos)? as usize;
        if skipped_count > SKIPPED_MAX {
            return Err(anyhow!("skipped pool too large"));
        }
        let mut skipped = HashMap::with_capacity(skipped_count);
        for _ in 0..skipped_count {
            let g = read_u32(bytes, &mut pos)?;
            let n = read_u32(bytes, &mut pos)?;
            let mk = read_fixed::<32>(bytes, &mut pos)?;
            skipped.insert((g, n), mk);
        }
        if pos != bytes.len() {
            return Err(anyhow!("trailing bytes in ratchet state"));
        }
        let peer_pub = decode_peer_pub(peer_id)?;
        let own_pub = own.public().as_bytes().to_owned();
        Ok(Self {
            own: own.clone(),
            own_pub,
            peer_id: peer_id.to_string(),
            peer_pub,
            gen,
            root,
            our_eph_priv,
            our_eph_pub,
            their_eph,
            prev_eph,
            send_ck,
            send_n,
            recv_ck,
            recv_n,
            prev_send_n,
            recv_bound,
            skipped,
            pending: None,
        })
    }

    fn encrypt_inner(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // 本代 eph 懒生成（首次发送 announce）。
        if self.our_eph_priv.is_none() {
            let (priv_bytes, pub_bytes) = new_eph();
            self.our_eph_priv = Some(priv_bytes);
            self.our_eph_pub = Some(pub_bytes);
        }
        // gen0 首条：把发送链绑定到本端临时 eph（X3DH 式）。
        // 只由静态-静态 root0 派生链的话，长期私钥一泄漏，全部 gen0 消息
        // 都能被离线解开；混入 DH(eph_own, pk_peer) 后，攻击者还需要本端
        // 临时 eph 私钥。幂等：同一 eph 重复加密得到同一条链。
        if self.gen == 0 && self.send_n == 0 {
            let dh = x25519_shared(
                self.our_eph_priv.as_ref().unwrap(),
                &peer_montgomery(&self.peer_pub)?,
            )?;
            self.send_ck = bind_chain(
                &self.root,
                &dh,
                chain_info(&self.own_pub, &self.peer_pub, true),
            );
        }
        // 收敛性发送刷新：已在本代发送过（send_n>0）且已收到对方本代 eph。
        if let Some((their_gen, their_pub)) = self.their_eph {
            if their_gen == self.gen && self.send_n > 0 {
                let dh = x25519_shared(self.our_eph_priv.as_ref().unwrap(), &their_pub)?;
                let new_root = kdf_rk(&self.root, &dh);
                let (send_ck, recv_ck) = derive_chains(&new_root, &self.own_pub, &self.peer_pub);
                self.prev_send_n = self.send_n;
                self.gen += 1;
                self.root = new_root;
                self.send_ck = send_ck;
                self.send_n = 0;
                self.recv_ck = recv_ck;
                self.recv_n = 0;
                // 刷新前的旧 eph 公钥固定为本代消息头携带的 prev_eph：
                // 对方即使从未收到本端旧代消息，也能凭它还原同一 root。
                self.prev_eph = *self.our_eph_pub.as_ref().unwrap();
                let (priv_bytes, pub_bytes) = new_eph();
                self.our_eph_priv = Some(priv_bytes);
                self.our_eph_pub = Some(pub_bytes);
                self.their_eph = None;
            }
        }
        let (next_ck, mk) = kdf_ck(&self.send_ck);
        self.send_ck = next_ck;
        let n = self.send_n;
        self.send_n += 1;

        let mut nonce = [0u8; 12];
        rand_core::OsRng.fill_bytes(&mut nonce);
        // 完整明文头作为 AEAD AAD，防止篡改 dh_pub/prev_eph/gen/n 等字段
        // 污染棘轮状态。先组头，再加密正文并把 tag 追加在密文末尾。
        let mut out = Vec::with_capacity(HEADER_LEN + plaintext.len() + 16);
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.gen.to_le_bytes());
        out.extend_from_slice(self.our_eph_pub.as_ref().unwrap());
        out.extend_from_slice(&n.to_le_bytes());
        out.extend_from_slice(&self.prev_send_n.to_le_bytes());
        out.extend_from_slice(&self.prev_eph);
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

    fn decrypt_inner(&mut self, blob: &[u8]) -> Result<Vec<u8>> {
        let hdr = parse_header(blob)?;

        // gen0 接收链绑定：与发送端 encrypt_inner 的绑定对称。
        // 用对方 header 里的 dh_pub 做 DH(sk_own, eph_peer)，只绑一次。
        if hdr.gen == 0 && self.gen == 0 && !self.recv_bound {
            let own_secret = own_x25519_secret(&self.own);
            let dh = x25519_shared(&own_secret, &hdr.dh_pub)?;
            self.recv_ck = bind_chain(
                &self.root,
                &dh,
                chain_info(&self.own_pub, &self.peer_pub, false),
            );
            self.recv_n = 0;
            self.recv_bound = true;
        }

        // 对方领先一代：收敛性接收刷新。
        if hdr.gen > self.gen {
            if hdr.gen != self.gen + 1 {
                return Err(anyhow!(
                    "gen gap too large: local {} vs remote {}",
                    self.gen,
                    hdr.gen
                ));
            }
            let our_priv = self
                .our_eph_priv
                .ok_or_else(|| anyhow!("no own eph for recv refresh"))?;
            // 用消息头冗余的 prev_eph（对方刷新所用的旧 eph 公钥）做 DH，
            // 而不是本地记录的 their_eph：即使漏收对方旧代消息也能还原 root。
            // X25519 对称性保证与发送方 DH(my_eph_old, their_eph) 相同。
            // 快进旧接收链到 header.pn，把迟到消息的密钥存入 skipped 池。
            // 本端可能从未收到对方 gen0 消息（离线漏收），接收链还没绑定。
            // 用 header.prev_eph（对方刷新前用的 eph，正绑 gen0 链的那个）
            // 补做一次绑定，否则快进出来的 skipped 密钥全是错的。
            if self.gen == 0 && !self.recv_bound {
                let own_secret = own_x25519_secret(&self.own);
                let dh0 = x25519_shared(&own_secret, &hdr.prev_eph)?;
                self.recv_ck = bind_chain(
                    &self.root,
                    &dh0,
                    chain_info(&self.own_pub, &self.peer_pub, false),
                );
                self.recv_n = 0;
                self.recv_bound = true;
            }
            if hdr.pn > self.recv_n {
                if hdr.pn - self.recv_n > MAX_SKIP {
                    return Err(anyhow!("pn fast-forward exceeds window"));
                }
                let mut ck = self.recv_ck;
                for i in self.recv_n..hdr.pn {
                    let (next, mk) = kdf_ck(&ck);
                    ck = next;
                    insert_skipped(&mut self.skipped, (self.gen, i), mk)?;
                }
            }
            let dh = x25519_shared(&our_priv, &hdr.prev_eph)?;
            let new_root = kdf_rk(&self.root, &dh);
            let (send_ck, recv_ck) = derive_chains(&new_root, &self.own_pub, &self.peer_pub);
            self.prev_send_n = self.send_n;
            self.gen = hdr.gen;
            self.root = new_root;
            self.send_ck = send_ck;
            self.send_n = 0;
            self.recv_ck = recv_ck;
            self.recv_n = 0;
            // 本端刷新前的旧 eph 公钥固定为本代携带值，供对方收敛刷新。
            self.prev_eph = *self.our_eph_pub.as_ref().unwrap();
            let (priv_bytes, pub_bytes) = new_eph();
            self.our_eph_priv = Some(priv_bytes);
            self.our_eph_pub = Some(pub_bytes);
            self.their_eph = Some((hdr.gen, hdr.dh_pub));
        }

        if hdr.gen == self.gen {
            // 同代消息同样 announce 对方本代 eph：记录以便下次发送时刷新。
            self.their_eph = Some((hdr.gen, hdr.dh_pub));
            let mk = if hdr.n >= self.recv_n {
                if hdr.n - self.recv_n > MAX_SKIP {
                    return Err(anyhow!(
                        "skip window exceeded: n {} vs recv_n {}",
                        hdr.n,
                        self.recv_n
                    ));
                }
                let mut ck = self.recv_ck;
                let mut mk = None;
                for i in self.recv_n..=hdr.n {
                    let (next, k) = kdf_ck(&ck);
                    ck = next;
                    if i == hdr.n {
                        mk = Some(k);
                    } else {
                        insert_skipped(&mut self.skipped, (self.gen, i), k)?;
                    }
                }
                self.recv_ck = ck;
                self.recv_n = hdr.n + 1;
                mk.expect("n within loop range")
            } else {
                // 同代迟到：从 skipped 池取用后销毁。
                self.skipped
                    .remove(&(self.gen, hdr.n))
                    .ok_or_else(|| anyhow!("message {} too old / already consumed", hdr.n))?
            };
            decrypt_aead(&mk, &hdr, blob)
        } else {
            // 跨代迟到（hdr.gen < self.gen）：只能从 skipped 池取用。
            let mk = self
                .skipped
                .remove(&(hdr.gen, hdr.n))
                .ok_or_else(|| anyhow!("message from stale gen {} too old", hdr.gen))?;
            decrypt_aead(&mk, &hdr, blob)
        }
    }
}

impl Clone for Ratchet {
    fn clone(&self) -> Self {
        Self {
            own: self.own.clone(),
            own_pub: self.own_pub,
            peer_id: self.peer_id.clone(),
            peer_pub: self.peer_pub,
            gen: self.gen,
            root: self.root,
            our_eph_priv: self.our_eph_priv,
            our_eph_pub: self.our_eph_pub,
            their_eph: self.their_eph,
            prev_eph: self.prev_eph,
            send_ck: self.send_ck,
            send_n: self.send_n,
            recv_ck: self.recv_ck,
            recv_n: self.recv_n,
            prev_send_n: self.prev_send_n,
            recv_bound: self.recv_bound,
            skipped: self.skipped.clone(),
            pending: None,
        }
    }
}

/// 生成新的临时 X25519 密钥对（私钥 + 公钥字节）。
fn new_eph() -> ([u8; 32], [u8; 32]) {
    let mut seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    let secret = StaticSecret::from(seed);
    let public = x25519_dalek::PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

/// 静态 ECDH + HKDF 派生 root₀。双方各自用 (私钥, 对方公钥) 计算同一根密钥。
fn root0(own: &iroh::SecretKey, peer_pub: &[u8; 32]) -> Result<[u8; 32]> {
    let signing: SigningKey = SigningKey::from_bytes(&own.to_bytes());
    let my_x25519: StaticSecret = signing.to_scalar_bytes().into();
    // Ed25519 公钥 → Montgomery 形式才可做 X25519 ECDH。
    let peer_ed: ed25519_dalek::VerifyingKey = ed25519_dalek::VerifyingKey::from_bytes(peer_pub)
        .map_err(|e| anyhow!("invalid peer key: {e}"))?;
    let peer_x25519 = x25519_dalek::PublicKey::from(peer_ed.to_montgomery().to_bytes());
    let shared = my_x25519.diffie_hellman(&peer_x25519);
    if shared.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(anyhow!("x25519 root0 shared secret is all-zero"));
    }
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut root = [0u8; 32];
    hk.expand(INFO_ROOT, &mut root)
        .map_err(|e| anyhow!("hkdf expand failed: {e}"))?;
    Ok(root)
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

/// X25519 共享密钥（DH(a,b)==DH(b,a)，收敛刷新与 gen0 绑定的关键）。
///
/// 输出全 0 说明对端给的是低阶点（`dh_pub` / `prev_eph` 未做点校验时
/// 会被利用来把 DH 退化成一个公开值），一律按错误处理。
fn x25519_shared(priv_bytes: &[u8; 32], pub_bytes: &[u8; 32]) -> Result<[u8; 32]> {
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
fn own_x25519_secret(own: &iroh::SecretKey) -> [u8; 32] {
    let signing: SigningKey = SigningKey::from_bytes(&own.to_bytes());
    signing.to_scalar_bytes()
}

/// 对端 Ed25519 公钥的 Montgomery 形式（X25519 用）。
fn peer_montgomery(peer_pub: &[u8; 32]) -> Result<[u8; 32]> {
    let peer_ed = ed25519_dalek::VerifyingKey::from_bytes(peer_pub)
        .map_err(|e| anyhow!("invalid peer key: {e}"))?;
    Ok(peer_ed.to_montgomery().to_bytes())
}

/// 按公钥字典序判定「本端是 low 侧还是 high 侧」，返回该方向的链 info。
/// `send = true` 取发送链，`false` 取接收链（两侧互为反方向）。
fn chain_info(own_pub: &[u8; 32], peer_pub: &[u8; 32], send: bool) -> &'static [u8] {
    let own_is_low = own_pub < peer_pub;
    match (own_is_low, send) {
        (true, true) => INFO_CHAIN_LOW,
        (true, false) => INFO_CHAIN_HIGH,
        (false, true) => INFO_CHAIN_HIGH,
        (false, false) => INFO_CHAIN_LOW,
    }
}

/// gen0 链绑定：`ck = HKDF(salt=root, ikm=DH, info=方向)`。
/// 发送侧用 `DH(eph_own, pk_peer)`，接收侧用 `DH(sk_own, eph_peer)`，二者相等。
fn bind_chain(root: &[u8; 32], dh: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(root), dh);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .expect("hkdf expand 32 bytes cannot fail");
    out
}

fn decrypt_aead(mk: &[u8; 32], header: &Header, blob: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(mk));
    cipher
        .decrypt(
            Nonce::from_slice(&header.nonce),
            Payload {
                msg: &blob[header.len..],
                aad: &blob[..header.len],
            },
        )
        .map_err(|e| anyhow!("decrypt failed: {e}"))
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

/// 解析消息头。只读，不消耗任何状态。
fn parse_header(blob: &[u8]) -> Result<Header> {
    if blob.len() < 5 || &blob[..4] != MAGIC {
        return Err(anyhow!("bad magic/version"));
    }
    let version = blob[4];
    if version != VERSION {
        return Err(anyhow!("bad magic/version"));
    }
    let len = HEADER_LEN;
    if blob.len() < HEADER_LEN {
        return Err(anyhow!("blob too short"));
    }
    let mut dh_pub = [0u8; 32];
    dh_pub.copy_from_slice(&blob[9..41]);
    let mut prev_eph = [0u8; 32];
    let mut nonce = [0u8; 12];
    prev_eph.copy_from_slice(&blob[49..81]);
    nonce.copy_from_slice(&blob[81..93]);
    Ok(Header {
        len,
        gen: u32::from_le_bytes(blob[5..9].try_into().unwrap()),
        dh_pub,
        n: u32::from_le_bytes(blob[41..45].try_into().unwrap()),
        pn: u32::from_le_bytes(blob[45..49].try_into().unwrap()),
        prev_eph,
        nonce,
    })
}

/// 解码对端 peer_id（hexlower 的 Ed25519 公钥）为 32 字节。
fn decode_peer_pub(peer_id: &str) -> Result<[u8; 32]> {
    let bytes = hex_decode(peer_id)?;
    // 校验是合法 Ed25519 公钥（防注入）。
    ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .map_err(|e| anyhow!("invalid peer key: {e}"))?;
    Ok(bytes)
}

fn hex_decode(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 {
        return Err(anyhow!("peer id must be 64 hex chars, got {}", s.len()));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_val(s.as_bytes()[i * 2])?;
        let lo = hex_val(s.as_bytes()[i * 2 + 1])?;
        *byte = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_val(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(anyhow!("invalid hex char: {}", b as char)),
    }
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
