use super::*;
use iroh::SecretKey;

/// 一对身份 + 一把 X25519 SPK（响应方持有私钥，发起方只有公钥）。
struct Fixture {
    alice: SecretKey,
    bob: SecretKey,
    alice_id: String,
    bob_id: String,
    spk_sk: [u8; 32],
    spk_pk: [u8; 32],
}

fn fixture() -> Fixture {
    let alice = SecretKey::generate();
    let bob = SecretKey::generate();
    let (spk_sk, spk_pk) = new_eph();
    Fixture {
        alice_id: alice.public().to_string(),
        bob_id: bob.public().to_string(),
        alice,
        bob,
        spk_sk,
        spk_pk,
    }
}

impl Fixture {
    fn a(&self) -> Ratchet {
        Ratchet::new_initiator(&self.alice, &self.bob_id, &self.spk_pk).unwrap()
    }
    fn b(&self) -> Ratchet {
        Ratchet::new_responder(&self.bob, &self.alice_id, &self.spk_sk).unwrap()
    }
}

/// 测试中每次 encrypt 都代表"发送成功"，因此须紧跟 next() 提交推进；
/// 与 app 层"送达确认后才 next()"的契约一致。
#[test]
fn roundtrip_in_order() {
    let f = fixture();
    let mut a = f.a();
    let mut b = f.b();

    // Alice 连发 3 条 gen0。
    let mut a_blobs = Vec::new();
    for text in ["a1", "a2", "a3"] {
        let blob = a.encrypt(text.as_bytes()).unwrap();
        a.next();
        let hdr = parse_header(&blob).unwrap();
        assert_eq!(hdr.gen, 0);
        assert_eq!(hdr.n, a_blobs.len() as u32);
        a_blobs.push(blob);
    }
    for (i, blob) in a_blobs.iter().enumerate() {
        assert_eq!(b.decrypt(blob).unwrap(), ["a1", "a2", "a3"][i].as_bytes());
    }
    assert!(b.is_established());

    // Bob 首条：send_n==0 → gen0 announce 自己的 eph。
    let b0 = b.encrypt(b"b1").unwrap();
    b.next();
    let h = parse_header(&b0).unwrap();
    assert_eq!((h.gen, h.n, h.pn), (0, 0, 0));
    assert_eq!(a.decrypt(&b0).unwrap(), b"b1");

    // Bob 第二条：已发（send_n>0）且已收对方 eph → 刷新到 gen1。
    let b1 = b.encrypt(b"b2").unwrap();
    b.next();
    let h = parse_header(&b1).unwrap();
    assert_eq!((h.gen, h.n, h.pn), (1, 0, 1));
    assert_eq!(a.decrypt(&b1).unwrap(), b"b2");

    // Alice 续发：接收刷新后 send_n 归零，本代仍为 gen1；pn = Alice gen0 发送数(3)。
    let a4 = a.encrypt(b"a4").unwrap();
    a.next();
    let h = parse_header(&a4).unwrap();
    assert_eq!((h.gen, h.n, h.pn), (1, 0, 3));
    assert_eq!(b.decrypt(&a4).unwrap(), b"a4");

    // Bob 续发：已在本代发送且已收对方本代 eph → 刷新到 gen2。
    let b2 = b.encrypt(b"b3").unwrap();
    b.next();
    let h = parse_header(&b2).unwrap();
    assert_eq!((h.gen, h.n, h.pn), (2, 0, 1));
    assert_eq!(a.decrypt(&b2).unwrap(), b"b3");
}

/// 响应方在收到发起方首条消息前不允许发送（会话尚未建立）。
#[test]
fn responder_cannot_send_before_first_message() {
    let f = fixture();
    let mut b = f.b();
    assert!(!b.is_established());
    assert!(b.encrypt(b"too early").is_err(), "must not send before X3DH");

    let mut a = f.a();
    let blob = a.encrypt(b"init").unwrap();
    a.next();
    assert_eq!(b.decrypt(&blob).unwrap(), b"init");
    assert!(b.is_established());
    assert!(b.encrypt(b"now ok").unwrap().len() > HEADER_LEN);
}

/// SPK 不对就派生不出 root₀。
#[test]
fn wrong_spk_cannot_decrypt() {
    let f = fixture();
    let mut a = f.a();
    let blob = a.encrypt(b"secret").unwrap();
    a.next();

    let (wrong_sk, _wrong_pk) = new_eph();
    let mut b = Ratchet::new_responder(&f.bob, &f.alice_id, &wrong_sk).unwrap();
    assert!(b.decrypt(&blob).is_err(), "wrong SPK must not derive root");
}

/// 只拿到响应方的 IK（没有 SPK 私钥）也不能派生 root₀。
#[test]
fn ik_alone_cannot_derive_root() {
    let f = fixture();
    let mut a = f.a();
    let blob = a.encrypt(b"top-secret").unwrap();

    // 攻击者有 bob 的 IK，但没有 bob 的 SPK 私钥。
    let (random_sk, _random_pk) = new_eph();
    let mut attacker = Ratchet::new_responder(&f.bob, &f.alice_id, &random_sk).unwrap();
    assert!(
        attacker.decrypt(&blob).is_err(),
        "IK alone must not derive the session root"
    );

    let mut b = f.b();
    assert_eq!(b.decrypt(&blob).unwrap(), b"top-secret");
}

#[test]
fn out_of_order_within_window() {
    let f = fixture();
    let mut a = f.a();
    let mut b = f.b();

    let mut blobs = Vec::new();
    for i in 0..10 {
        blobs.push(a.encrypt(format!("m{i}").as_bytes()).unwrap());
        a.next();
    }
    // 乱序交付（逆序）。
    for (i, blob) in blobs.iter().enumerate().rev() {
        assert_eq!(b.decrypt(blob).unwrap(), format!("m{i}").as_bytes());
    }
    // 取用后即销毁：同一 blob 重放必须失败。
    assert!(b.decrypt(&blobs[0]).is_err(), "replay must fail");
}

#[test]
fn skip_window_exceeded_is_rejected() {
    let f = fixture();
    let mut a = f.a();
    let mut b = f.b();

    let mut blobs = Vec::new();
    for i in 0..(MAX_SKIP + 5) {
        blobs.push(a.encrypt(format!("m{i}").as_bytes()).unwrap());
        a.next();
    }
    // 一条没收，直接跳超过 MAX_SKIP → 必须失败（防 DoS）。
    let res = b.decrypt(&blobs[MAX_SKIP as usize + 1]);
    assert!(res.is_err(), "skip beyond window must fail");
    // 失败不推进状态：之后按序解密前几条仍正常。
    assert_eq!(b.decrypt(&blobs[0]).unwrap(), b"m0");
    assert_eq!(b.decrypt(&blobs[1]).unwrap(), b"m1");
}

#[test]
fn restart_resume() {
    let f = fixture();
    let mut a = f.a();
    let mut b = f.b();

    let a0 = a.encrypt(b"a0").unwrap();
    a.next();
    assert_eq!(b.decrypt(&a0).unwrap(), b"a0");
    let b0 = b.encrypt(b"b0").unwrap();
    b.next();
    assert_eq!(a.decrypt(&b0).unwrap(), b"b0");
    let a1 = a.encrypt(b"a1").unwrap();
    a.next();
    let b1 = b.encrypt(b"b1").unwrap();
    b.next();
    assert_eq!(a.decrypt(&b1).unwrap(), b"b1");
    assert_eq!(b.decrypt(&a1).unwrap(), b"a1");

    // 双方序列化并重建（模拟重启）。
    let a_state = a.to_bytes();
    let b_state = b.to_bytes();
    let mut a2 = Ratchet::from_bytes(&f.alice, &f.bob_id, &a_state).unwrap();
    let mut b2 = Ratchet::from_bytes(&f.bob, &f.alice_id, &b_state).unwrap();

    let a2_blob = a2.encrypt(b"a2").unwrap();
    a2.next();
    assert_eq!(b2.decrypt(&a2_blob).unwrap(), b"a2");
    let b2_blob = b2.encrypt(b"b2").unwrap();
    b2.next();
    assert_eq!(a2.decrypt(&b2_blob).unwrap(), b"b2");
}

#[test]
fn state_roundtrip_is_stable() {
    let f = fixture();
    let mut a = f.a();
    let mut b = f.b();
    let b_x = a.encrypt(b"x").unwrap();
    a.next();
    let b_y = a.encrypt(b"y").unwrap();
    a.next();
    let blobs = [b_x, b_y];
    for blob in &blobs {
        b.decrypt(blob).unwrap();
    }

    let state = b.to_bytes();
    let mut b2 = Ratchet::from_bytes(&f.bob, &f.alice_id, &state).unwrap();
    // 序列化往返后行为一致。
    let blob = a.encrypt(b"z").unwrap();
    a.next();
    assert_eq!(b2.decrypt(&blob).unwrap(), b"z");

    // 篡改状态必须报错。
    let mut bad = state.clone();
    bad[0] ^= 0xff;
    assert!(Ratchet::from_bytes(&f.bob, &f.alice_id, &bad).is_err());
}

#[test]
fn third_party_cannot_read() {
    let f = fixture();
    let mallory = SecretKey::generate();
    let mut a = f.a();
    let (m_sk, _m_pk) = new_eph();
    let mut m = Ratchet::new_responder(&mallory, &f.alice_id, &m_sk).unwrap();
    let blob = a.encrypt(b"secret").unwrap();
    assert!(m.decrypt(&blob).is_err(), "mallory must not decrypt");
}

#[test]
fn tamper_detected_and_state_unpoisoned() {
    let f = fixture();
    let mut a = f.a();
    let mut b = f.b();

    let mut blob = a.encrypt(b"hello").unwrap();
    a.next();
    let last_cipher_byte = blob.len() - SIG_LEN - 1;
    blob[last_cipher_byte] ^= 0x01;
    assert!(b.decrypt(&blob).is_err(), "tampered blob must fail");

    // 失败不推进状态：重新加密的同一消息（n=1，含 skipped 池还原）仍可解密。
    let good = a.encrypt(b"hello").unwrap();
    a.next();
    assert_eq!(Ratchet::header_gen_n(&good).unwrap(), (0, 1));
    assert_eq!(b.decrypt(&good).unwrap(), b"hello");
    let next = a.encrypt(b"next").unwrap();
    a.next();
    assert_eq!(b.decrypt(&next).unwrap(), b"next");
}

#[test]
fn header_tamper_detected_and_state_unpoisoned() {
    let f = fixture();
    let mut a = f.a();
    let mut b = f.b();

    let good = a.encrypt(b"hello").unwrap();
    a.next();
    let mut tampered = good.clone();
    tampered[9] ^= 0x01; // 仅篡改同代 dh_pub；正文和 nonce 保持不变。
    assert!(
        b.decrypt(&tampered).is_err(),
        "tampered header must fail authentication"
    );

    // 失败不记录伪造 eph、不推进接收链，原消息仍可正常解密。
    assert_eq!(b.decrypt(&good).unwrap(), b"hello");
    let next = a.encrypt(b"next").unwrap();
    a.next();
    assert_eq!(b.decrypt(&next).unwrap(), b"next");
}

#[test]
fn failed_send_does_not_advance_chain() {
    let f = fixture();
    let mut a = f.a();
    let mut b = f.b();

    // 模拟发送失败：encrypt 后不调用 next()（状态保持加密前）。
    let blob = a.encrypt(b"msg").unwrap();
    let hdr = parse_header(&blob).unwrap();
    assert_eq!((hdr.gen, hdr.n), (0, 0));

    // 重试：仍从同一 (gen, n) 加密，二者等价，对端可按序解密。
    let retry = a.encrypt(b"msg").unwrap();
    assert_eq!(Ratchet::header_gen_n(&retry).unwrap(), (0, 0));
    assert_eq!(b.decrypt(&blob).unwrap(), b"msg");
    assert!(b.decrypt(&retry).is_err(), "same (gen,n) is a replay");

    // 送达后再提交，推进正常生效。
    a.next();
    let blob2 = a.encrypt(b"msg2").unwrap();
    assert_eq!(Ratchet::header_gen_n(&blob2).unwrap(), (0, 1));
    assert_eq!(b.decrypt(&blob2).unwrap(), b"msg2");
}

#[test]
fn has_valid_prefix_works() {
    let f = fixture();
    let mut a = f.a();
    let blob = a.encrypt(b"x").unwrap();
    assert!(Ratchet::has_valid_prefix(&blob));
    assert!(!Ratchet::has_valid_prefix(b"garbage"));
    let mut bad = blob.clone();
    bad[4] = 9;
    assert!(!Ratchet::has_valid_prefix(&bad));
}

#[test]
fn header_length_and_gen_n() {
    let f = fixture();
    let mut a = f.a();
    let blob = a.encrypt(b"x").unwrap();
    a.next();
    let hdr = parse_header(&blob).unwrap();
    assert_eq!(blob.len(), HEADER_LEN + SIG_LEN + 1 + 16); // ct 1B + tag 16B + sig 64B
    assert_eq!(hdr.gen, 0);
    assert_eq!(hdr.n, 0);
    assert_eq!(Ratchet::header_gen_n(&blob).unwrap(), (0, 0));

    let _ = a.encrypt(b"y").unwrap();
    a.next();
    let blob3 = a.encrypt(b"z").unwrap();
    a.next();
    assert_eq!(Ratchet::header_gen_n(&blob3).unwrap(), (0, 2));

    // 对方刷新后 gen 递增，且 n 重新从 0 计。
    let mut b = f.b();
    let _ = b.decrypt(&blob).unwrap();
    let b0 = b.encrypt(b"b0").unwrap();
    b.next();
    let b1 = b.encrypt(b"b1").unwrap();
    b.next();
    assert_eq!(Ratchet::header_gen_n(&b0).unwrap(), (0, 0));
    assert_eq!(Ratchet::header_gen_n(&b1).unwrap(), (1, 0));
}

/// 签名被篡改必须在进入棘轮前被拒绝（不消耗状态）。
#[test]
fn signature_tamper_is_rejected() {
    let f = fixture();
    let mut a = f.a();
    let mut b = f.b();

    let good = a.encrypt(b"signed").unwrap();
    a.next();
    let mut bad = good.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    assert!(b.decrypt(&bad).is_err(), "bad signature must be rejected");

    // 状态未被污染：原消息仍可正常解密。
    assert_eq!(b.decrypt(&good).unwrap(), b"signed");
}

/// 用别人的密钥重签同一条消息，验签必须失败（身份绑定生效）。
#[test]
fn wrong_signer_is_rejected() {
    let f = fixture();
    let mut a = f.a();
    let blob = a.encrypt(b"from-alice").unwrap();

    let mallory = SecretKey::generate();
    let body_end = blob.len() - SIG_LEN;
    let mut forged = blob.clone();
    let sig = sign_body(&mallory, &forged[..body_end]);
    forged[body_end..].copy_from_slice(&sig);

    let mut b = f.b();
    assert!(
        b.decrypt(&forged).is_err(),
        "signature from another key must be rejected"
    );
    assert_eq!(b.decrypt(&blob).unwrap(), b"from-alice");
}
