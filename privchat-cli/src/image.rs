//! 图片收发子命令（分块、清单、sha256 校验）。

use super::*;

pub(crate) async fn cmd_send_image(
    home: &Path,
    from: &str,
    to: &str,
    path: &str,
    mailbox: &str,
    relays: Vec<String>,
    chunk_size: usize,
) -> Result<()> {
    let data = fs::read(path).with_context(|| format!("读取图片失败: {path}"))?;
    if data.is_empty() {
        bail!("图片为空");
    }
    let file_name = Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "image.bin".into());
    let sha = sha256_hex(&data);
    let chunk = chunk_size.max(1024);
    let chunks = data.len().div_ceil(chunk);
    let manifest = json!({
        "v": 1, "type": "img-manifest", "name": file_name,
        "size": data.len(), "sha256": sha, "chunks": chunks, "chunk_size": chunk,
        "ts": now_ms(),
    });

    let (label, peer, spk) = resolve_contact(home, from, to)?;
    let secret = identity_for(home, from, &label)?;
    let mut ratchet = load_ratchet(home, &secret, from, &peer, spk.as_deref())?;
    // P0：图片发送同样用一次性连接身份。
    let endpoint = make_endpoint(SecretKey::generate()).await?;

    let started = Instant::now();
    let (mid, _) = deliver(
        home,
        from,
        &secret,
        &peer,
        manifest.to_string().as_bytes(),
        mailbox,
        &relays,
        &endpoint,
        &mut ratchet,
    )
    .await?;
    println!(
        "manifest msg_id={mid} size={}B chunks={chunks} sha256={sha}",
        data.len()
    );

    for (i, piece) in data.chunks(chunk).enumerate() {
        let (mid, len) = deliver(
            home,
            from,
            &secret,
            &peer,
            piece,
            mailbox,
            &relays,
            &endpoint,
            &mut ratchet,
        )
        .await?;
        println!(
            "  chunk {}/{} msg_id={mid} ciphertext={len}B",
            i + 1,
            chunks
        );
    }
    endpoint.close().await;
    let route = if relays.is_empty() { "direct" } else { "onion" };
    println!(
        "image sent: {chunks} chunks in {}ms route={route}",
        started.elapsed().as_millis()
    );
    Ok(())
}

pub(crate) async fn cmd_recv_image(
    home: &Path,
    name: &str,
    mailbox: &str,
    only_peer: Option<&str>,
    out: Option<&str>,
) -> Result<()> {
    let msgs = recv_all(home, name, mailbox, only_peer).await?;
    let mut manifest: Option<Value> = None;
    let mut chunks: Vec<(u64, Vec<u8>)> = Vec::new();
    for m in &msgs {
        if let Ok(v) = serde_json::from_slice::<Value>(&m.plain) {
            if v.get("type").and_then(|t| t.as_str()) == Some("img-manifest") {
                manifest = Some(v);
                continue;
            }
        }
        chunks.push((msg_order(&m.msg_id).1, m.plain.clone()));
    }
    let manifest = manifest.ok_or_else(|| anyhow!("未收到图片清单（img-manifest）"))?;
    let expect = manifest["chunks"].as_u64().unwrap_or(0) as usize;
    if chunks.len() != expect {
        bail!("分块数量不符：收到 {}，应为 {expect}", chunks.len());
    }
    chunks.sort_by_key(|(i, _)| *i);
    let mut data = Vec::new();
    for (_, piece) in &chunks {
        data.extend_from_slice(piece);
    }
    let expect_sha = manifest["sha256"].as_str().unwrap_or_default();
    let actual = sha256_hex(&data);
    if actual != expect_sha {
        bail!("sha256 校验失败：期望 {expect_sha}，实际 {actual}");
    }
    // 清单里的文件名来自对端，必须只取最后一段，防止 `../` 路径穿越。
    let raw_name = manifest["name"].as_str().unwrap_or("image.bin");
    let safe_name = Path::new(raw_name)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .filter(|s| !s.is_empty() && s != ".." && s != ".")
        .unwrap_or_else(|| "image.bin".into());
    let out_path = PathBuf::from(out.unwrap_or(&safe_name));
    fs::write(&out_path, &data)?;
    println!(
        "image received: {} bytes -> {} (sha256 ok)",
        data.len(),
        out_path.display()
    );
    Ok(())
}
