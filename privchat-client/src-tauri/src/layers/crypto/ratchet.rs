//! 双棘轮：链推进、DH 刷新、消息编解码与状态序列化。

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use super::*;

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
    /// 发起方选用的 OPK id（0 = 没用；写进每条消息头）。
    opk_id: u64,
    /// 响应方待用的 OPK 私钥（收到首条消息后清空，一次性）。
    opk_sk: Option<[u8; 32]>,
    /// 响应方待派生状态：本端 SPK 私钥。收到发起方首条消息（含 EK）后
    /// 用它还原 root₀，随后清空。为 `Some` 时表示会话尚未建立、不能发送。
    pending_spk: Option<[u8; 32]>,
    /// 滑动窗口池：`(gen, n) -> 消息密钥`，取用后删除。
    skipped: HashMap<(u32, u32), [u8; 32]>,
    /// 待提交的发送推进：`encrypt` 只在试算副本上推进并暂存于此，
    /// 由上层确认消息送达（`next`）后提交，发送失败则不提交。
    pending: Option<Box<Ratchet>>,
}

impl Ratchet {
    /// 发起方建会话：已知对端 SPK 公钥，立即生成会话 EK 并派生 root₀。
    ///
    /// `peer_spk` 是 X25519 公钥（Montgomery 形式），由邀请串携带并用
    /// 对端 IK 签名保护。root₀ 由三组 DH 混合：
    ///   DH(IK_own, SPK_peer) || DH(EK, IK_peer) || DH(EK, SPK_peer)
    pub fn new_initiator(
        own: &iroh::SecretKey,
        peer_id: &str,
        peer_spk: &[u8; 32],
        opk: Option<(&[u8; 32], u64)>,
    ) -> Result<Self> {
        let peer_pub = decode_peer_pub(peer_id)?;
        let own_pub = own.public().as_bytes().to_owned();
        let (ek_priv, ek_pub) = new_eph();
        let root = x3dh_root_initiator(own, &peer_pub, peer_spk, &ek_priv, opk.map(|(pk, _)| pk))?;
        let (send_ck, recv_ck) = derive_chains(&root, &own_pub, &peer_pub);
        Ok(Self {
            own: own.clone(),
            own_pub,
            peer_id: peer_id.to_string(),
            peer_pub,
            gen: 0,
            root,
            our_eph_priv: Some(ek_priv),
            our_eph_pub: Some(ek_pub),
            their_eph: None,
            prev_eph: [0u8; 32],
            send_ck,
            send_n: 0,
            recv_ck,
            recv_n: 0,
            prev_send_n: 0,
            pending_spk: None,
            opk_id: opk.map(|(_, id)| id).unwrap_or(0),
            opk_sk: None,
            skipped: HashMap::new(),
            pending: None,
        })
    }

    /// 响应方建会话：只知道自己的 SPK 私钥，root₀ 要等对方首条消息
    /// （header 里带会话 EK）才能派生。在此之前 `encrypt` 会报错。
    pub fn new_responder(
        own: &iroh::SecretKey,
        peer_id: &str,
        own_spk_sk: &[u8; 32],
        opk: Option<(&[u8; 32], u64)>,
    ) -> Result<Self> {
        let peer_pub = decode_peer_pub(peer_id)?;
        let own_pub = own.public().as_bytes().to_owned();
        Ok(Self {
            own: own.clone(),
            own_pub,
            peer_id: peer_id.to_string(),
            peer_pub,
            gen: 0,
            root: [0u8; 32],
            our_eph_priv: None,
            our_eph_pub: None,
            their_eph: None,
            prev_eph: [0u8; 32],
            send_ck: [0u8; 32],
            send_n: 0,
            recv_ck: [0u8; 32],
            recv_n: 0,
            prev_send_n: 0,
            pending_spk: Some(*own_spk_sk),
            opk_id: opk.map(|(_, id)| id).unwrap_or(0),
            opk_sk: opk.map(|(sk, _)| *sk),
            skipped: HashMap::new(),
            pending: None,
        })
    }

    /// 本端作为发起方时，本会话的 EK 公钥（用于计算 session_id）。
    pub fn own_ek(&self) -> Option<[u8; 32]> {
        self.our_eph_pub
    }

    /// 会话是否已建立（响应方收到发起方首条消息前为 false）。
    pub fn is_established(&self) -> bool {
        self.pending_spk.is_none()
    }

    /// 加密一段明文，返回带头的密文 blob。推进在试算副本上完成后暂存
    /// 于 `pending`，不立即提交：由上层确认消息送达后调用 [`next`] 提交，
    /// 发送失败则不调用（自然回滚，不污染会话链）。
    ///
    /// [`next`]: Ratchet::next
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if self.pending_spk.is_some() {
            return Err(anyhow!(
                "session not established: waiting for initiator's first message"
            ));
        }
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
            p.root = self.root;
            p.pending_spk = self.pending_spk;
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
        let flags = u8::from(self.our_eph_priv.is_some())
            | (u8::from(self.their_eph.is_some()) << 1)
            | (u8::from(self.pending_spk.is_some()) << 2);
        out.push(flags);
        if let Some(priv_bytes) = self.our_eph_priv {
            out.extend_from_slice(&priv_bytes);
            out.extend_from_slice(self.our_eph_pub.as_ref().unwrap());
        }
        if let Some((g, pub_bytes)) = self.their_eph {
            out.extend_from_slice(&g.to_le_bytes());
            out.extend_from_slice(&pub_bytes);
        }
        if let Some(spk_sk) = self.pending_spk {
            out.extend_from_slice(&spk_sk);
        }
        out.extend_from_slice(&self.prev_eph);
        out.extend_from_slice(&self.send_ck);
        out.extend_from_slice(&self.send_n.to_le_bytes());
        out.extend_from_slice(&self.recv_ck);
        out.extend_from_slice(&self.recv_n.to_le_bytes());
        out.extend_from_slice(&self.prev_send_n.to_le_bytes());
        out.extend_from_slice(&self.opk_id.to_le_bytes());
        match self.opk_sk {
            Some(sk) => {
                out.push(1);
                out.extend_from_slice(&sk);
            }
            None => out.push(0),
        }
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
        let has_pending_spk = flags & 4 == 4;
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
        let pending_spk = if has_pending_spk {
            Some(read_fixed::<32>(bytes, &mut pos)?)
        } else {
            None
        };
        let prev_eph = read_fixed::<32>(bytes, &mut pos)?;
        let send_ck = read_fixed::<32>(bytes, &mut pos)?;
        let send_n = read_u32(bytes, &mut pos)?;
        let recv_ck = read_fixed::<32>(bytes, &mut pos)?;
        let recv_n = read_u32(bytes, &mut pos)?;
        let prev_send_n = read_u32(bytes, &mut pos)?;
        let mut opk_bytes = [0u8; 8];
        opk_bytes.copy_from_slice(
            bytes
                .get(pos..pos + 8)
                .ok_or_else(|| anyhow!("truncated state"))?,
        );
        pos += 8;
        let opk_id = u64::from_le_bytes(opk_bytes);
        let opk_sk = if read_u8(bytes, &mut pos)? == 1 {
            Some(read_fixed::<32>(bytes, &mut pos)?)
        } else {
            None
        };
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
            opk_id,
            opk_sk,
            pending_spk,
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
        out.extend_from_slice(&self.opk_id.to_le_bytes());
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
        // 末尾追加发送方身份签名：覆盖 header + ciphertext。
        let sig = sign_body(&self.own, &out);
        out.extend_from_slice(&sig);
        Ok(out)
    }

    fn decrypt_inner(&mut self, blob: &[u8]) -> Result<Vec<u8>> {
        let hdr = parse_header(blob)?;
        if blob.len() < HEADER_LEN + SIG_LEN {
            return Err(anyhow!("blob too short for signature"));
        }
        // 先验签，再动任何棘轮状态：伪造/篡改的消息在进入绑定与解密前就被拒。
        let body_end = blob.len() - SIG_LEN;
        verify_body(&self.peer_pub, &blob[..body_end], &blob[body_end..])?;

        // 响应方首条消息：用 header 里的会话 EK 完成 X3DH，派生 root₀。
        // gen0 消息的 EK 在 dh_pub；若漏收了 gen0、直接收到 gen1，
        // 发起方刷新前用的 EK 在 prev_eph 里。
        if let Some(spk_sk) = self.pending_spk {
            let ek_pub = if hdr.gen == 0 {
                hdr.dh_pub
            } else if hdr.gen == 1 {
                hdr.prev_eph
            } else {
                return Err(anyhow!(
                    "cannot derive session: message from gen {}",
                    hdr.gen
                ));
            };
            if hdr.opk_id != self.opk_id {
                return Err(anyhow!(
                    "OPK mismatch: header {} vs local {}",
                    hdr.opk_id,
                    self.opk_id
                ));
            }
            let root = x3dh_root_responder(
                &self.own,
                &self.peer_pub,
                &spk_sk,
                &ek_pub,
                self.opk_sk.as_ref(),
            )?;
            let (send_ck, recv_ck) = derive_chains(&root, &self.own_pub, &self.peer_pub);
            self.root = root;
            self.gen = 0;
            self.send_ck = send_ck;
            self.send_n = 0;
            self.recv_ck = recv_ck;
            self.recv_n = 0;
            self.prev_send_n = 0;
            self.their_eph = None;
            self.prev_eph = [0u8; 32];
            self.pending_spk = None;
            // OPK 一次性：派生完就丢。
            self.opk_sk = None;
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
            decrypt_aead(&mk, &hdr, blob, body_end)
        } else {
            // 跨代迟到（hdr.gen < self.gen）：只能从 skipped 池取用。
            let mk = self
                .skipped
                .remove(&(hdr.gen, hdr.n))
                .ok_or_else(|| anyhow!("message from stale gen {} too old", hdr.gen))?;
            decrypt_aead(&mk, &hdr, blob, body_end)
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
            opk_id: self.opk_id,
            opk_sk: self.opk_sk,
            pending_spk: self.pending_spk,
            skipped: self.skipped.clone(),
            pending: None,
        }
    }
}
