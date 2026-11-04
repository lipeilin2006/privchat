//! 密码学层：
//! - [`connection`]：SimpleX 式「每连接独立密钥」的会话（单 DH + 对称棘轮）；
//! - [`hex`]：十六进制编解码。
//!
//! 旧的全局身份 / X3DH / SPK / OPK / 每消息签名那一套已删除。

pub mod connection;
pub mod hex;

pub use hex::{hex_decode, hex_encode};
