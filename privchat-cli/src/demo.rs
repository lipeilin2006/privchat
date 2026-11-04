//! 端到端自检：两个身份走一遍 mailbox 往返。

use super::*;

pub(crate) async fn cmd_demo(home: &Path, mailbox: &str) -> Result<()> {
    let demo_home = home.join("demo");
    fs::create_dir_all(&demo_home)?;
    for f in fs::read_dir(&demo_home)?.flatten() {
        let _ = fs::remove_file(f.path());
    }
    let alice = SecretKey::generate();
    let bob = SecretKey::generate();
    fs::write(key_path(&demo_home, "alice"), alice.to_bytes())?;
    fs::write(key_path(&demo_home, "bob"), bob.to_bytes())?;
    let alice_id = peer_id_of(&alice);
    let bob_id = peer_id_of(&bob);
    fs::write(
        demo_home.join("bob.contacts"),
        format!("{alice_id} {alice_id} {}\n", hex_of(&cli_spk_pub(&alice))),
    )?;
    fs::write(
        demo_home.join("alice.contacts"),
        format!("{bob_id} {bob_id} {}\n", hex_of(&cli_spk_pub(&bob))),
    )?;
    println!("demo identities\n  alice: {alice_id}\n  bob  : {bob_id}");

    let text = format!("hello from alice @ {}", now_ms());
    let t0 = Instant::now();
    let (msg_id, cipher_len) = {
        let secret = alice.clone();
        let mut ratchet = Ratchet::new_initiator(&secret, &bob_id, &cli_spk_pub(&bob), None)?;
        let endpoint = make_endpoint(SecretKey::generate()).await?;
        let body = json!({"v":1,"type":"text","ts":now_ms(),"text":text}).to_string();
        let r = deliver(
            &demo_home,
            "alice",
            &secret,
            &bob_id,
            body.as_bytes(),
            mailbox,
            &[],
            &endpoint,
            &mut ratchet,
        )
        .await;
        endpoint.close().await;
        r?
    };
    println!("\n1) alice -> bob\n   msg_id={msg_id} ciphertext={cipher_len}B");

    let received = recv_all(&demo_home, "bob", mailbox, Some(&alice_id)).await?;
    println!("\n2) bob fetch + decrypt");
    let mut ok = false;
    for m in &received {
        let v: Value = serde_json::from_slice(&m.plain)?;
        println!("   from={} ciphertext={}B", m.peer, m.cipher_len);
        println!("   plaintext={}", v["text"].as_str().unwrap_or_default());
        if v["text"].as_str() == Some(text.as_str()) {
            ok = true;
        }
    }
    println!(
        "\nresult: {} ({} ms)",
        if ok { "PASS" } else { "FAIL" },
        t0.elapsed().as_millis()
    );
    if !ok {
        bail!("端到端校验失败");
    }
    Ok(())
}
