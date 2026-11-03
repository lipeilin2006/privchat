use super::*;
use iroh::SecretKey;

fn peers() -> (SecretKey, SecretKey, String, String) {
    let alice = SecretKey::generate();
    let bob = SecretKey::generate();
    let bob_id = bob.public().to_string();
    let alice_id = alice.public().to_string();
    (alice, bob, bob_id, alice_id)
}

/// 测试中每次 encrypt 都代表"发送成功"，因此须紧跟 next() 提交推进；
/// 与 app 层"送达确认后才 next()"的契约一致。
#[test]
fn roundtrip_in_order() {
    let (alice, bob, bob_id, alice_id) = peers();
    let mut a = Ratchet::new(&alice, &bob_id).unwrap();
    let mut b = Ratchet::new(&bob, &alice_id).unwrap();

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

    // Bob 首条：send_n==0 → 必须 gen0 announce 自己的 eph。
    let b0 = b.encrypt(b"b1").unwrap();
    b.next();
    let h = parse_header(&b0).unwrap();
    assert_eq!((h.gen, h.n, h.pn), (0, 0, 0));
    assert_eq!(a.decrypt(&b0).unwrap(), b"b1");

    // Bob 第二条：已发（send_n>0）且已收对方 eph → 刷新到 gen1，
    // pn = Bob gen0 发送数(1)。Alice 凭 b0 里的 B0 可还原同一 root。
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

#[test]
fn concurrent_first_send_converges() {
    let (alice, bob, bob_id, alice_id) = peers();
    let mut a = Ratchet::new(&alice, &bob_id).unwrap();
    let mut b = Ratchet::new(&bob, &alice_id).unwrap();

    // 双方各自先发（互不知晓对方 eph）。
    let a_blob0 = a.encrypt(b"a0").unwrap();
    let b_blob0 = b.encrypt(b"b0").unwrap();

    // 交换：先收对方首条（gen0），再发（各自刷新到 gen1）。
    assert_eq!(b.decrypt(&a_blob0).unwrap(), b"a0");
    assert_eq!(a.decrypt(&b_blob0).unwrap(), b"b0");
    a.next();
    b.next();
    let a_blob1 = a.encrypt(b"a1").unwrap();
    let b_blob1 = b.encrypt(b"b1").unwrap();
    assert_eq!(parse_header(&a_blob1).unwrap().gen, 1);
    assert_eq!(parse_header(&b_blob1).unwrap().gen, 1);
    assert_eq!(a.decrypt(&b_blob1).unwrap(), b"b1");
    assert_eq!(b.decrypt(&a_blob1).unwrap(), b"a1");
    a.next();
    b.next();

    // gen1 上继续多轮交错收发，验证收敛不漂移。
    for i in 2..8 {
        let a_blob = a.encrypt(format!("a{i}").as_bytes()).unwrap();
        let b_blob = b.encrypt(format!("b{i}").as_bytes()).unwrap();
        assert_eq!(a.decrypt(&b_blob).unwrap(), format!("b{i}").as_bytes());
        assert_eq!(b.decrypt(&a_blob).unwrap(), format!("a{i}").as_bytes());
        a.next();
        b.next();
    }
}

#[test]
fn offline_burst_then_reply_converges() {
    let (alice, bob, bob_id, alice_id) = peers();
    let mut a = Ratchet::new(&alice, &bob_id).unwrap();
    let mut b = Ratchet::new(&bob, &alice_id).unwrap();

    // Alice 离线连发多条 gen0（n=0..4）。
    let mut blobs = Vec::new();
    for i in 0..5 {
        blobs.push(a.encrypt(format!("a{i}").as_bytes()).unwrap());
        a.next();
        assert_eq!(parse_header(blobs.last().unwrap()).unwrap().gen, 0);
    }
    // Bob 一次性全收。
    for (i, blob) in blobs.iter().enumerate() {
        assert_eq!(b.decrypt(blob).unwrap(), format!("a{i}").as_bytes());
    }
    // Bob 回复首条：send_n==0 → 必须 gen0 announce 自己 eph。
    let b0 = b.encrypt(b"b0").unwrap();
    b.next();
    assert_eq!(parse_header(&b0).unwrap().gen, 0);
    assert_eq!(a.decrypt(&b0).unwrap(), b"b0");
    // Bob 第二条：已 send 且收到对方 eph → gen1。
    let b1 = b.encrypt(b"b1").unwrap();
    b.next();
    assert_eq!(parse_header(&b1).unwrap().gen, 1);
    assert_eq!(a.decrypt(&b1).unwrap(), b"b1");
}

#[test]
fn out_of_order_within_window() {
    let (alice, bob, bob_id, alice_id) = peers();
    let mut a = Ratchet::new(&alice, &bob_id).unwrap();
    let mut b = Ratchet::new(&bob, &alice_id).unwrap();

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
    let (alice, bob, bob_id, alice_id) = peers();
    let mut a = Ratchet::new(&alice, &bob_id).unwrap();
    let mut b = Ratchet::new(&bob, &alice_id).unwrap();

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
    let (alice, bob, bob_id, alice_id) = peers();
    let mut a = Ratchet::new(&alice, &bob_id).unwrap();
    let mut b = Ratchet::new(&bob, &alice_id).unwrap();

    let a0 = a.encrypt(b"a0").unwrap();
    a.next();
    let b0 = b.encrypt(b"b0").unwrap();
    b.next();
    assert_eq!(a.decrypt(&b0).unwrap(), b"b0");
    assert_eq!(b.decrypt(&a0).unwrap(), b"a0");
    let a1 = a.encrypt(b"a1").unwrap();
    a.next();
    let b1 = b.encrypt(b"b1").unwrap();
    b.next();
    assert_eq!(a.decrypt(&b1).unwrap(), b"b1");
    assert_eq!(b.decrypt(&a1).unwrap(), b"a1");

    // 双方序列化并重建（模拟重启）。
    let a_state = a.to_bytes();
    let b_state = b.to_bytes();
    let mut a2 = Ratchet::from_bytes(&alice, &bob_id, &a_state).unwrap();
    let mut b2 = Ratchet::from_bytes(&bob, &alice_id, &b_state).unwrap();

    // 重启后继续收发（此时双方已刷新到 gen1）。
    let a2_blob = a2.encrypt(b"a2").unwrap();
    a2.next();
    assert_eq!(b2.decrypt(&a2_blob).unwrap(), b"a2");
    let b2_blob = b2.encrypt(b"b2").unwrap();
    b2.next();
    assert_eq!(a2.decrypt(&b2_blob).unwrap(), b"b2");
}

#[test]
fn state_roundtrip_is_stable() {
    let (alice, bob, bob_id, alice_id) = peers();
    let mut a = Ratchet::new(&alice, &bob_id).unwrap();
    let mut b = Ratchet::new(&bob, &alice_id).unwrap();
    let b_x = a.encrypt(b"x").unwrap();
    a.next();
    let b_y = a.encrypt(b"y").unwrap();
    a.next();
    let blobs = [b_x, b_y];
    for blob in &blobs {
        b.decrypt(blob).unwrap();
    }

    let state = b.to_bytes();
    let mut b2 = Ratchet::from_bytes(&bob, &alice_id, &state).unwrap();
    // 序列化往返后行为一致。
    let blob = a.encrypt(b"z").unwrap();
    a.next();
    assert_eq!(b2.decrypt(&blob).unwrap(), b"z");

    // 篡改状态必须报错。
    let mut bad = state.clone();
    bad[0] ^= 0xff;
    assert!(Ratchet::from_bytes(&bob, &alice_id, &bad).is_err());
}

#[test]
fn third_party_cannot_read() {
    let (alice, _bob, bob_id, _alice_id) = peers();
    let mallory = SecretKey::generate();
    let mut a = Ratchet::new(&alice, &bob_id).unwrap();
    let mut m = Ratchet::new(&mallory, &bob_id).unwrap();
    let blob = a.encrypt(b"secret").unwrap();
    assert!(m.decrypt(&blob).is_err(), "mallory must not decrypt");
}

#[test]
fn tamper_detected_and_state_unpoisoned() {
    let (alice, bob, bob_id, alice_id) = peers();
    let mut a = Ratchet::new(&alice, &bob_id).unwrap();
    let mut b = Ratchet::new(&bob, &alice_id).unwrap();

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
    let (alice, bob, bob_id, alice_id) = peers();
    let mut a = Ratchet::new(&alice, &bob_id).unwrap();
    let mut b = Ratchet::new(&bob, &alice_id).unwrap();

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
    let (alice, bob, bob_id, alice_id) = peers();
    let mut a = Ratchet::new(&alice, &bob_id).unwrap();
    let mut b = Ratchet::new(&bob, &alice_id).unwrap();

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
    let (alice, _bob, bob_id, _alice_id) = peers();
    let mut a = Ratchet::new(&alice, &bob_id).unwrap();
    let blob = a.encrypt(b"x").unwrap();
    assert!(Ratchet::has_valid_prefix(&blob));
    assert!(!Ratchet::has_valid_prefix(b"garbage"));
    let mut bad = blob.clone();
    bad[4] = 9;
    assert!(!Ratchet::has_valid_prefix(&bad));
}

#[test]
fn v4_header_and_gen_n() {
    let (alice, bob, bob_id, alice_id) = peers();
    let mut a = Ratchet::new(&alice, &bob_id).unwrap();
    let blob = a.encrypt(b"x").unwrap();
    a.next();
    let hdr = parse_header(&blob).unwrap();
    assert_eq!(blob.len(), HEADER_LEN + SIG_LEN + 1 + 16); // ct 1B + tag 16B + sig 64B
    assert_eq!(hdr.gen, 0);
    assert_eq!(hdr.n, 0);
    assert_eq!(Ratchet::header_gen_n(&blob).unwrap(), (0, 0));
    // 加密 3 条后 n 递增；header_gen_n 反映 (gen, n) 发送序。
    let _ = a.encrypt(b"y").unwrap();
    a.next();
    let blob3 = a.encrypt(b"z").unwrap();
    a.next();
    assert_eq!(Ratchet::header_gen_n(&blob3).unwrap(), (0, 2));

    // 对方刷新后 gen 递增，且 n 重新从 0 计。
    let mut b = Ratchet::new(&bob, &alice_id).unwrap();
    let _ = b.decrypt(&blob).unwrap();
    let b0 = b.encrypt(b"b0").unwrap();
    b.next();
    let b1 = b.encrypt(b"b1").unwrap();
    b.next();
    assert_eq!(Ratchet::header_gen_n(&b0).unwrap(), (0, 0));
    assert_eq!(Ratchet::header_gen_n(&b1).unwrap(), (1, 0));
}

/// 离线/乱序失步回归：B 从未收到 A 的旧代消息（msg1 携带 eph_A0），
/// 直接收到 A 的换代消息（gen1）。旧实现依赖 their_eph 报
/// 换代消息头冗余携带
/// prev_eph，B 凭 DH(own_eph_priv, header.prev_eph) 原地补课。
#[test]
fn offline_missed_old_eph_still_converges() {
    let (alice, bob, bob_id, alice_id) = peers();
    let mut a = Ratchet::new(&alice, &bob_id).unwrap();
    let mut b = Ratchet::new(&bob, &alice_id).unwrap();

    // A 发 msg1（gen0, eph_A0）到 mailbox，B 一直没拉取（从未见过 eph_A0）。
    let msg1 = a.encrypt(b"a1").unwrap();
    a.next();
    assert_eq!(parse_header(&msg1).unwrap().gen, 0);

    // B 上线后没拉 msg1，自己先发 msg2（gen0, eph_B0）。
    let msg2 = b.encrypt(b"b1").unwrap();
    b.next();
    assert_eq!(parse_header(&msg2).unwrap().gen, 0);

    // A 收到 msg2 后发起换代（gen1），消息头带 prev_eph=eph_A0。
    assert_eq!(a.decrypt(&msg2).unwrap(), b"b1");
    let msg3 = a.encrypt(b"a2").unwrap();
    a.next();
    let hdr = parse_header(&msg3).unwrap();
    assert_eq!(hdr.gen, 1);
    assert_ne!(hdr.prev_eph, [0u8; 32], "refresh msg must carry prev_eph");

    // 关键断言：B 从未收到 msg1，仅凭 msg3 头里的 prev_eph 也能解密。
    assert_eq!(b.decrypt(&msg3).unwrap(), b"a2");

    // 后续双向通信正常，且迟到的 msg1 也能按序/乱序补收（pn 快进 + skipped）。
    let msg4 = b.encrypt(b"b2").unwrap();
    b.next();
    assert_eq!(a.decrypt(&msg4).unwrap(), b"b2");
    assert_eq!(b.decrypt(&msg1).unwrap(), b"a1");
}

/// gen0 绑定（X3DH 式）的安全回归：只拿到长期私钥的攻击者，
/// 按「静态-静态 root0 直接派生链」的老办法解 gen0 消息必须失败。
/// 否则长期私钥泄漏就能回溯解开全部 gen0 / 单向会话消息。
#[test]
fn long_term_key_alone_cannot_open_gen0() {
    let (alice, _bob, bob_id, _alice_id) = peers();
    let mut a = Ratchet::new(&alice, &bob_id).unwrap();
    let blob = a.encrypt(b"top-secret").unwrap();

    // 攻击者视角：有 alice 的长期私钥 + bob 的公开 peer_id。
    let peer_pub = decode_peer_pub(&bob_id).unwrap();
    let root = root0(&alice, &peer_pub).unwrap();
    let (send_ck, _) = derive_chains(&root, alice.public().as_bytes(), &peer_pub);
    let (_, mk) = kdf_ck(&send_ck);
    let hdr = parse_header(&blob).unwrap();
    assert!(
        decrypt_aead(&mk, &hdr, &blob, blob.len() - SIG_LEN).is_err(),
        "leaked long-term key alone must not open gen0 messages"
    );

    // 正常接收方仍然能解（绑定链由 header.dh_pub 还原）。
    let mut b = Ratchet::new(&_bob, &_alice_id).unwrap();
    assert_eq!(b.decrypt(&blob).unwrap(), b"top-secret");
}

/// 签名被篡改必须在进入棘轮前被拒绝（不消耗状态）。
#[test]
fn signature_tamper_is_rejected() {
    let (alice, bob, bob_id, alice_id) = peers();
    let mut a = Ratchet::new(&alice, &bob_id).unwrap();
    let mut b = Ratchet::new(&bob, &alice_id).unwrap();

    let good = a.encrypt(b"signed").unwrap();
    a.next();
    let mut bad = good.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    assert!(b.decrypt(&bad).is_err(), "bad signature must be rejected");

    // 状态未被污染：原消息仍可正常解密。
    assert_eq!(b.decrypt(&good).unwrap(), b"signed");
}

/// 冒名者用自己的密钥签名、冒充发送方身份，必须验签失败。
#[test]
fn wrong_signer_is_rejected() {
    let (alice, _bob, bob_id, alice_id) = peers();
    let mut a = Ratchet::new(&alice, &bob_id).unwrap();
    let blob = a.encrypt(b"from-alice").unwrap();

    // mallory 用「bob 视角下 alice 的身份」建棘轮（同一 peer_pub），
    // 但消息是 alice 的密钥签的？—— 这里反过来：换一个签名者。
    let mallory = SecretKey::generate();
    let mut m = Ratchet::new(&mallory, &alice_id).unwrap();
    let forged = m.encrypt(b"from-alice").unwrap();

    // bob 用 alice 的公钥验签 → mallory 的签名不通过。
    let mut b = Ratchet::new(&_bob, &alice_id).unwrap();
    assert!(b.decrypt(&forged).is_err(), "wrong signer must be rejected");
    assert_eq!(b.decrypt(&blob).unwrap(), b"from-alice");
}
