//! 消息头：固定前缀的编解码。
//!
//! ```text
//! [0..4] magic | [4] version | [5..9] gen | [9..41] dh_pub
//! [41..45] n | [45..49] pn | [49..57] opk_id u64 | [57..89] prev_eph | [89..101] nonce
//! ```

use anyhow::{anyhow, Result};

pub(super) const MAGIC: &[u8; 4] = b"PRR6";
pub(super) const VERSION: u8 = 8;
pub(super) const HEADER_LEN: usize = 101;
pub(super) const SIG_LEN: usize = 64;

/// 解析后的消息头。
#[derive(Clone, Copy)]
pub(super) struct Header {
    pub(super) len: usize,
    pub(super) gen: u32,
    pub(super) dh_pub: [u8; 32],
    pub(super) n: u32,
    pub(super) pn: u32,
    /// 发起方选用的 OPK id（0 = 没用一次性预密钥）。
    pub(super) opk_id: u64,
    pub(super) prev_eph: [u8; 32],
    pub(super) nonce: [u8; 12],
}

/// 解析消息头。只读，不消耗任何状态。
pub(super) fn parse_header(blob: &[u8]) -> Result<Header> {
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
    prev_eph.copy_from_slice(&blob[57..89]);
    nonce.copy_from_slice(&blob[89..101]);
    Ok(Header {
        len,
        gen: u32::from_le_bytes(blob[5..9].try_into().unwrap()),
        dh_pub,
        n: u32::from_le_bytes(blob[41..45].try_into().unwrap()),
        pn: u32::from_le_bytes(blob[45..49].try_into().unwrap()),
        opk_id: u64::from_le_bytes(blob[49..57].try_into().unwrap()),
        prev_eph,
        nonce,
    })
}

/// 消息头里发起方选用的 OPK id（0 = 没用）。
pub fn header_opk_id(blob: &[u8]) -> Result<u64> {
    Ok(parse_header(blob)?.opk_id)
}
