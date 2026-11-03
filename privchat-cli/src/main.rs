//! PrivChat 命令行测试客户端（含洋葱路由与图片发送）
//!
//! 复用 `privchat-client` 的真实双棘轮加密（`layers::crypto::Ratchet`）与
//! `privchat-common` 的 mailbox wire 协议，在没有 GUI 的服务器上验证：
//!
//! ```text
//! 身份 -> 双棘轮加密 -> [洋葱多层封装 -> 逐跳中继] -> mailbox PUT
//! 身份 -> mailbox FETCH -> 双棘轮解密 -> 文本 / 图片重组
//! ```
//!
//! 用法见 README。

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use iroh::SecretKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use privchat_client_lib::layers::crypto::Ratchet;
use privchat_common::{find_pow, make_endpoint, send_request, MailboxRequest, MailboxResponse};
use privchat_onion::{wrap, ONION_ALPN};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn home() -> PathBuf {
    if let Ok(v) = std::env::var("PRIVCHAT_CLI_HOME") {
        return PathBuf::from(v);
    }
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".privchat-cli")
}

fn key_path(home: &Path, name: &str) -> PathBuf {
    home.join(format!("{name}.key"))
}

fn ratchet_path(home: &Path, name: &str, peer: &str) -> PathBuf {
    home.join(format!("{name}@{peer}.ratchet"))
}

fn load_secret(home: &Path, name: &str) -> Result<SecretKey> {
    let path = key_path(home, name);
    let bytes = fs::read(&path).with_context(|| {
        format!(
            "身份 {name} 不存在（找不到 {}），先运行 `privchat-cli init {name}`",
            path.display()
        )
    })?;
    SecretKey::try_from(bytes.as_slice()).map_err(|e| anyhow!("读取身份失败: {e}"))
}

fn peer_id_of(secret: &SecretKey) -> String {
    secret.public().to_string()
}

/// 状态文件头：magic + version + 归属身份公钥，防止身份串用与版本漂移。
const STATE_MAGIC: &[u8; 4] = b"PRST";
const STATE_VERSION: u8 = 1;
const STATE_HEADER: usize = 4 + 1 + 32;

fn state_wrap(secret: &SecretKey, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(STATE_HEADER + payload.len());
    out.extend_from_slice(STATE_MAGIC);
    out.push(STATE_VERSION);
    out.extend_from_slice(secret.public().as_bytes());
    out.extend_from_slice(payload);
    out
}

fn state_unwrap(secret: &SecretKey, path: &Path, raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() < STATE_HEADER || &raw[0..4] != STATE_MAGIC {
        bail!("{} 不是合法的 PrivChat 状态文件（magic 不匹配）", path.display());
    }
    if raw[4] != STATE_VERSION {
        bail!(
            "{} 状态版本 {} 不受支持（期望 {}）",
            path.display(),
            raw[4],
            STATE_VERSION
        );
    }
    if &raw[5..37] != secret.public().as_bytes() {
        bail!("{} 属于另一个身份，拒绝加载（防止身份串用）", path.display());
    }
    Ok(raw[STATE_HEADER..].to_vec())
}

fn load_ratchet(home: &Path, secret: &SecretKey, name: &str, peer: &str) -> Result<Ratchet> {
    let path = ratchet_path(home, name, peer);
    if path.exists() {
        let raw = fs::read(&path)?;
        let bytes = state_unwrap(secret, &path, &raw)?;
        Ratchet::from_bytes(secret, peer, &bytes)
            .with_context(|| format!("恢复会话 {} 失败", path.display()))
    } else {
        Ratchet::new(secret, peer)
    }
}

fn save_ratchet(
    home: &Path,
    name: &str,
    peer: &str,
    secret: &SecretKey,
    ratchet: &Ratchet,
) -> Result<()> {
    fs::create_dir_all(home)?;
    fs::write(ratchet_path(home, name, peer), state_wrap(secret, &ratchet.to_bytes()))?;
    Ok(())
}

/// 该身份已知的对端 peer_id 列表（联系人表 + 本地会话文件）。
fn known_peers(home: &Path, name: &str) -> Result<Vec<String>> {
    let mut out: Vec<String> = contacts(home, name)?
        .into_iter()
        .map(|(_, peer)| peer)
        .collect();
    let prefix = format!("{name}@");
    if let Ok(entries) = fs::read_dir(home) {
        for entry in entries.flatten() {
            let file = entry.file_name().to_string_lossy().to_string();
            if let Some(rest) = file.strip_prefix(&prefix) {
                if let Some(peer) = rest.strip_suffix(".ratchet") {
                    out.push(peer.to_string());
                }
            }
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn contact_key_path(home: &Path, name: &str, label: &str) -> PathBuf {
    home.join(format!("{name}@{label}.id"))
}

/// 联系人表：每行 `<label> <peer_id>`；只写一个字段时视为 label == peer_id。
fn contacts(home: &Path, name: &str) -> Result<Vec<(String, String)>> {
    let path = home.join(format!("{name}.contacts"));
    let mut out = Vec::new();
    if let Ok(text) = fs::read_to_string(path) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut it = line.split_whitespace();
            let first = it.next().unwrap_or_default();
            match it.next() {
                Some(peer) => out.push((first.to_string(), peer.to_string())),
                None => out.push((first.to_string(), first.to_string())),
            }
        }
    }
    Ok(out)
}

/// 把 `<label>` 或完整 peer_id 解析成 `(label, peer_id)`。
fn resolve_contact(home: &Path, name: &str, arg: &str) -> Result<(String, String)> {
    if let Some((label, peer)) = contacts(home, name)?
        .into_iter()
        .find(|(label, peer)| label == arg || peer == arg)
    {
        return Ok((label, peer));
    }
    if arg.len() == 64 && arg.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok((arg.to_string(), arg.to_string()));
    }
    bail!("找不到联系人 {arg}：先执行 `contact {name} <label> <peer_id>`")
}

/// 该身份在此联系人下使用的私钥：有专属身份用专属的，否则退回主身份。
fn identity_for(home: &Path, name: &str, label: &str) -> Result<SecretKey> {
    let path = contact_key_path(home, name, label);
    if path.exists() {
        let bytes = fs::read(&path)?;
        return SecretKey::try_from(bytes.as_slice())
            .map_err(|e| anyhow!("读取专属身份失败: {e}"));
    }
    load_secret(home, name)
}

/// 本地全部身份槽位：主身份 + 每个联系人一份专属身份。
struct IdentitySlot {
    secret: SecretKey,
    label: String,
}

fn identities_for(home: &Path, name: &str) -> Result<Vec<IdentitySlot>> {
    let mut slots = vec![IdentitySlot {
        secret: load_secret(home, name)?,
        label: "self".into(),
    }];
    let prefix = format!("{name}@");
    let mut files: Vec<String> = fs::read_dir(home)?
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .filter(|file| file.starts_with(&prefix) && file.ends_with(".id"))
        .collect();
    files.sort();
    for file in files {
        let label = file[prefix.len()..file.len() - 3].to_string();
        let bytes = fs::read(home.join(&file))?;
        let secret = SecretKey::try_from(bytes.as_slice())
            .map_err(|e| anyhow!("读取专属身份 {file} 失败: {e}"))?;
        slots.push(IdentitySlot { secret, label });
    }
    Ok(slots)
}

/// 为某个联系人生成专属身份（对应客户端「每个联系人一个身份」）。
fn cmd_derive(home: &Path, name: &str, label: &str) -> Result<()> {
    load_secret(home, name)?;
    let path = contact_key_path(home, name, label);
    if path.exists() {
        let bytes = fs::read(&path)?;
        let secret = SecretKey::try_from(bytes.as_slice())?;
        println!("derived identity already exists: {label}");
        println!("  peer_id : {}", peer_id_of(&secret));
        return Ok(());
    }
    let secret = SecretKey::generate();
    fs::write(&path, secret.to_bytes())?;
    println!("derived identity for {name}@{label}");
    println!("  peer_id : {}", peer_id_of(&secret));
    println!("  key     : {}", path.display());
    Ok(())
}

#[derive(Default)]
struct Args {
    positional: Vec<String>,
    mailbox: Option<String>,
    from: Option<String>,
    peer: Option<String>,
    relay: Option<String>,
    out: Option<String>,
    chunk: Option<usize>,
}

fn parse_args(raw: Vec<String>) -> Args {
    let mut args = Args::default();
    let mut it = raw.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--mailbox" => args.mailbox = it.next(),
            "--from" => args.from = it.next(),
            "--peer" => args.peer = it.next(),
            "--relay" => args.relay = it.next(),
            "--out" => args.out = it.next(),
            "--chunk" => args.chunk = it.next().and_then(|v| v.parse().ok()),
            _ => args.positional.push(a),
        }
    }
    args
}

fn relays_of(args: &Args) -> Vec<String> {
    args.relay
        .as_deref()
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// `msg_id` 形如 `gen:n`，解析成可排序元组。
fn msg_order(msg_id: &str) -> (u64, u64) {
    let mut parts = msg_id.split(':');
    let gen = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
    let n = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
    (gen, n)
}

async fn deliver(
    home: &Path,
    name: &str,
    secret: &SecretKey,
    to: &str,
    body: &[u8],
    mailbox: &str,
    relays: &[String],
    endpoint: &iroh::Endpoint,
    ratchet: &mut Ratchet,
) -> Result<(String, usize)> {
    let padded = privchat_common::pad_plaintext(body);
    let blob = ratchet.encrypt(&padded)?;
    let (gen, n) = Ratchet::header_gen_n(&blob)?;
    let msg_id = format!("{gen}:{n}");
    let nonce = find_pow(to, &blob);
    let req = MailboxRequest::put(to, &msg_id, blob.clone(), nonce);

    if relays.is_empty() {
        let resp = send_request(endpoint, mailbox, &req).await?;
        if !resp.ok {
            bail!("mailbox 拒绝: {}", resp.error.unwrap_or_default());
        }
    } else {
        let request = serde_json::to_vec(&req)?;
        let packet = wrap(relays, &request)?;
        send_onion(endpoint, &relays[0], &packet).await?;
    }

    ratchet.next();
    save_ratchet(home, name, to, secret, ratchet)?;
    Ok((msg_id, blob.len()))
}

/// 把洋葱包发给第一跳，等待中继或终点的响应。
async fn send_onion(endpoint: &iroh::Endpoint, first: &str, packet: &[u8]) -> Result<()> {
    let id: iroh::EndpointId = first
        .parse()
        .map_err(|_| anyhow!("relay peer id 解析失败: {first}"))?;
    let conn = tokio::time::timeout(
        Duration::from_secs(120),
        endpoint.connect(iroh::EndpointAddr::new(id), ONION_ALPN),
    )
    .await
    .map_err(|_| anyhow!("连接首跳 {first} 超时"))??;
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(packet).await?;
    send.finish()?;
    let bytes = tokio::time::timeout(Duration::from_secs(120), recv.read_to_end(4096))
        .await
        .map_err(|_| anyhow!("等待中继响应超时"))??;
    let response: MailboxResponse = serde_json::from_slice(&bytes)
        .map_err(|e| anyhow!("中继响应解析失败: {e}"))?;
    if !response.ok {
        bail!("洋葱链路失败: {}", response.error.unwrap_or_default());
    }
    Ok(())
}

struct Received {
    msg_id: String,
    peer: String,
    plain: Vec<u8>,
    cipher_len: usize,
}

/// 拉取并解密本端待收消息（按身份槽位逐条队列拉取，二进制安全）。
async fn recv_all(
    home: &Path,
    name: &str,
    mailbox: &str,
    only_peer: Option<&str>,
) -> Result<Vec<Received>> {
    let slots = identities_for(home, name)?;
    let candidates = match only_peer {
        Some(p) => vec![p.to_string()],
        None => known_peers(home, name)?,
    };

    let mut out = Vec::new();
    for slot in &slots {
        let me = peer_id_of(&slot.secret);
        let endpoint = make_endpoint(slot.secret.clone()).await?;
        let resp = send_request(&endpoint, mailbox, &MailboxRequest::fetch(&me)).await;
        endpoint.close().await;
        let resp = match resp {
            Ok(resp) => resp,
            Err(error) => {
                if slots.len() == 1 {
                    return Err(error);
                }
                eprintln!("[recv] 队列 {}({}) 拉取失败: {error:#}", slot.label, &me[..8]);
                continue;
            }
        };
        if !resp.ok {
            if slots.len() == 1 {
                bail!("mailbox 拒绝: {}", resp.error.unwrap_or_default());
            }
            eprintln!("[recv] 队列 {}({}) 被拒绝: {}", slot.label, &me[..8], resp.error.unwrap_or_default());
            continue;
        }
        for m in resp.messages.unwrap_or_default() {
            let cipher_len = m.msg.len();
            let mut decrypted = None;
            for peer in &candidates {
                let Ok(mut ratchet) = load_ratchet(home, &slot.secret, name, peer) else {
                    continue;
                };
                if let Ok(raw) = ratchet.decrypt(&m.msg) {
                    let plain = privchat_common::unpad_plaintext(&raw);
                    save_ratchet(home, name, peer, &slot.secret, &ratchet)?;
                    decrypted = Some((peer.clone(), plain));
                    break;
                }
            }
            let (peer, plain) = match decrypted {
                Some(v) => v,
                None => bail!(
                    "{} 字节密文解密失败（队列 {}）：请先用 `contact` 登记发送方，或加 --peer",
                    cipher_len,
                    &me[..8]
                ),
            };
            out.push(Received {
                msg_id: m.msg_id,
                peer,
                plain,
                cipher_len,
            });
        }
    }
    out.sort_by_key(|m| msg_order(&m.msg_id));
    Ok(out)
}

async fn cmd_init(home: &Path, name: &str) -> Result<()> {
    fs::create_dir_all(home)?;
    let path = key_path(home, name);
    if path.exists() {
        bail!("身份 {name} 已存在：{}", path.display());
    }
    let secret = SecretKey::generate();
    fs::write(&path, secret.to_bytes())?;
    println!("created identity {name}");
    println!("  peer_id : {}", peer_id_of(&secret));
    println!("  key     : {}", path.display());
    Ok(())
}

fn cmd_id(home: &Path, name: &str) -> Result<()> {
    println!("{}", peer_id_of(&load_secret(home, name)?));
    Ok(())
}

fn cmd_ls(home: &Path) -> Result<()> {
    if !home.exists() {
        println!("(无本地状态：{})", home.display());
        return Ok(());
    }
    let mut identities = Vec::new();
    let mut sessions = Vec::new();
    for entry in fs::read_dir(home)?.flatten() {
        let file = entry.file_name().to_string_lossy().to_string();
        if let Some(name) = file.strip_suffix(".key") {
            identities.push(name.to_string());
        } else if file.ends_with(".ratchet") {
            sessions.push(file);
        }
    }
    identities.sort();
    sessions.sort();
    println!("identities ({}):", identities.len());
    for name in identities {
        let secret = load_secret(home, &name)?;
        println!("  {name} -> {}", peer_id_of(&secret));
    }
    println!("sessions ({}):", sessions.len());
    for s in sessions {
        println!("  {s}");
    }
    Ok(())
}

fn cmd_contact(home: &Path, name: &str, label_or_peer: &str, peer: Option<&str>) -> Result<()> {
    load_secret(home, name)?;
    let (label, peer_id) = match peer {
        Some(peer) => (label_or_peer.to_string(), peer.to_string()),
        None => (label_or_peer.to_string(), label_or_peer.to_string()),
    };
    if peer_id.len() != 64 {
        bail!("peer id 应为 64 位十六进制");
    }
    let path = home.join(format!("{name}.contacts"));
    let mut existing = fs::read_to_string(&path).unwrap_or_default();
    let already = contacts(home, name)?
        .iter()
        .any(|(l, p)| l == &label || p == &peer_id);
    if !already {
        if !existing.ends_with('\n') && !existing.is_empty() {
            existing.push('\n');
        }
        existing.push_str(&format!("{label} {peer_id}\n"));
        fs::write(&path, existing)?;
    }
    println!("contact added: {name} {label} -> {peer_id}");
    Ok(())
}

/// 校验状态文件：magic / 版本 / 归属身份是否匹配（P3 的可观测入口）。
fn cmd_state(home: &Path, name: &str, label: &str) -> Result<()> {
    let (label, peer) = resolve_contact(home, name, label)?;
    let secret = identity_for(home, name, &label)?;
    let path = ratchet_path(home, name, &peer);
    if !path.exists() {
        bail!("状态文件不存在: {}", path.display());
    }
    let raw = fs::read(&path)?;
    let payload = state_unwrap(&secret, &path, &raw)?;
    println!(
        "state ok: {} (magic=PRST v{}, owner matches, payload={}B)",
        path.display(),
        raw[4],
        payload.len()
    );
    Ok(())
}

async fn cmd_ping(home: &Path, mailbox: &str, from: Option<&str>) -> Result<()> {
    let secret = match from {
        Some(name) => load_secret(home, name)?,
        None => SecretKey::generate(),
    };
    let endpoint = make_endpoint(secret).await?;
    let started = Instant::now();
    let resp = send_request(
        &endpoint,
        mailbox,
        &MailboxRequest {
            op: privchat_common::Op::Ping,
            to: None,
            for_peer: None,
            id: None,
            ids: None,
            payload: None,
            nonce: None,
            msg: None,
        },
    )
    .await;
    endpoint.close().await;
    let resp = resp?;
    println!(
        "ping ok={} rtt={}ms error={:?}",
        resp.ok,
        started.elapsed().as_millis(),
        resp.error
    );
    Ok(())
}

async fn cmd_send(
    home: &Path,
    from: &str,
    to: &str,
    text: &str,
    mailbox: &str,
    relays: Vec<String>,
) -> Result<()> {
    let (label, peer) = resolve_contact(home, from, to)?;
    let secret = identity_for(home, from, &label)?;
    let mut ratchet = load_ratchet(home, &secret, from, &peer)?;
    // P0：连接身份一次性生成，不暴露发送方的长期 iroh 身份。
    let endpoint = make_endpoint(SecretKey::generate()).await?;
    let body = json!({"v": 1, "type": "text", "ts": now_ms(), "text": text}).to_string();
    let route = if relays.is_empty() {
        "direct".to_string()
    } else {
        format!("onion({} hops)", relays.len())
    };
    let (msg_id, cipher_len) = deliver(
        home, from, &secret, &peer, body.as_bytes(), mailbox, &relays, &endpoint, &mut ratchet,
    )
    .await?;
    endpoint.close().await;
    println!("sent msg_id={msg_id} ciphertext={cipher_len}B route={route}");
    Ok(())
}

async fn cmd_recv(home: &Path, name: &str, mailbox: &str, only_peer: Option<&str>) -> Result<()> {
    let started = Instant::now();
    let msgs = recv_all(home, name, mailbox, only_peer).await?;
    println!("recv {} message(s) in {}ms", msgs.len(), started.elapsed().as_millis());
    for m in msgs {
        match serde_json::from_slice::<Value>(&m.plain) {
            Ok(v) if v.get("text").is_some() => {
                println!("  [{}] from={} ciphertext={}B", m.msg_id, m.peer, m.cipher_len);
                println!("  {}", v["text"].as_str().unwrap_or_default());
            }
            _ => println!(
                "  [{}] from={} ciphertext={}B <非文本 {}B>",
                m.msg_id, m.peer, m.cipher_len, m.plain.len()
            ),
        }
    }
    Ok(())
}

async fn cmd_send_image(
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

    let (label, peer) = resolve_contact(home, from, to)?;
    let secret = identity_for(home, from, &label)?;
    let mut ratchet = load_ratchet(home, &secret, from, &peer)?;
    // P0：图片发送同样用一次性连接身份。
    let endpoint = make_endpoint(SecretKey::generate()).await?;

    let started = Instant::now();
    let (mid, _) = deliver(
        home, from, &secret, &peer, manifest.to_string().as_bytes(), mailbox, &relays, &endpoint,
        &mut ratchet,
    )
    .await?;
    println!(
        "manifest msg_id={mid} size={}B chunks={chunks} sha256={sha}",
        data.len()
    );

    for (i, piece) in data.chunks(chunk).enumerate() {
        let (mid, len) = deliver(
            home, from, &secret, &peer, piece, mailbox, &relays, &endpoint, &mut ratchet,
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

async fn cmd_recv_image(
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

async fn cmd_demo(home: &Path, mailbox: &str) -> Result<()> {
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
    fs::write(demo_home.join("bob.contacts"), format!("{alice_id}\n"))?;
    fs::write(demo_home.join("alice.contacts"), format!("{bob_id}\n"))?;
    println!("demo identities\n  alice: {alice_id}\n  bob  : {bob_id}");

    let text = format!("hello from alice @ {}", now_ms());
    let t0 = Instant::now();
    let (msg_id, cipher_len) = {
        let secret = alice.clone();
        let mut ratchet = Ratchet::new(&secret, &bob_id)?;
        let endpoint = make_endpoint(SecretKey::generate()).await?;
        let body = json!({"v":1,"type":"text","ts":now_ms(),"text":text}).to_string();
        let r = deliver(
            &demo_home, "alice", &secret, &bob_id, body.as_bytes(), mailbox, &[], &endpoint,
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

#[tokio::main]
async fn main() -> Result<()> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.is_empty() {
        eprintln!(
            "usage:\n\
             \x20 privchat-cli init <name>\n\
             \x20 privchat-cli id <name>\n\
             \x20 privchat-cli ls\n\
             \x20 privchat-cli contact <name> <label> [peer_id]\n\
             \x20 privchat-cli derive <name> <label>\n\
             \x20 privchat-cli state <name> <label>\n\
             \x20 privchat-cli ping <mailbox> [--from N]\n\
             \x20 privchat-cli send <from> <to> <text> --mailbox <peer> [--relay id1,id2]\n\
             \x20 privchat-cli recv <name> --mailbox <peer> [--peer <sender>]\n\
             \x20 privchat-cli send-image <from> <to> <file> --mailbox <peer> [--relay id1,id2] [--chunk N]\n\
             \x20 privchat-cli recv-image <name> --mailbox <peer> [--peer <sender>] [--out file]\n\
             \x20 privchat-cli demo <mailbox>"
        );
        std::process::exit(2);
    }
    let home = home();
    fs::create_dir_all(&home)?;
    let args = parse_args(raw);
    let pos = &args.positional;
    let relays = relays_of(&args);
    match pos[0].as_str() {
        "init" => cmd_init(&home, pos.get(1).context("init 需要 <name>")?).await,
        "id" => cmd_id(&home, pos.get(1).context("id 需要 <name>")?),
        "ls" => cmd_ls(&home),
        "contact" => {
            if pos.len() < 3 {
                bail!("用法: contact <name> <label> [peer_id]");
            }
            cmd_contact(&home, &pos[1], &pos[2], pos.get(3).map(|s| s.as_str()))
        }
        "derive" => {
            if pos.len() < 3 {
                bail!("用法: derive <name> <peer_id>");
            }
            cmd_derive(&home, &pos[1], &pos[2])
        }
        "state" => {
            if pos.len() < 3 {
                bail!("用法: state <name> <label>");
            }
            cmd_state(&home, &pos[1], &pos[2])
        }
        "ping" => {
            let mailbox = pos.get(1).context("ping 需要 <mailbox_peer_id>")?;
            cmd_ping(&home, mailbox, args.from.as_deref()).await
        }
        "send" => {
            let mailbox = args.mailbox.as_deref().context("send 需要 --mailbox <peer>")?;
            if pos.len() < 4 {
                bail!("用法: send <from> <to> <text> --mailbox <peer>");
            }
            cmd_send(&home, &pos[1], &pos[2], &pos[3], mailbox, relays).await
        }
        "recv" => {
            let mailbox = args.mailbox.as_deref().context("recv 需要 --mailbox <peer>")?;
            let name = pos.get(1).context("recv 需要 <name>")?;
            let peer = match args.peer.as_deref() {
                Some(arg) => Some(resolve_contact(&home, name, arg)?.1),
                None => None,
            };
            cmd_recv(&home, name, mailbox, peer.as_deref()).await
        }
        "send-image" => {
            let mailbox = args
                .mailbox
                .as_deref()
                .context("send-image 需要 --mailbox <peer>")?;
            if pos.len() < 4 {
                bail!("用法: send-image <from> <to> <file> --mailbox <peer>");
            }
            let chunk = args.chunk.unwrap_or(8192);
            cmd_send_image(&home, &pos[1], &pos[2], &pos[3], mailbox, relays, chunk).await
        }
        "recv-image" => {
            let mailbox = args
                .mailbox
                .as_deref()
                .context("recv-image 需要 --mailbox <peer>")?;
            let name = pos.get(1).context("recv-image 需要 <name>")?;
            let peer = match args.peer.as_deref() {
                Some(arg) => Some(resolve_contact(&home, name, arg)?.1),
                None => None,
            };
            cmd_recv_image(&home, name, mailbox, peer.as_deref(), args.out.as_deref()).await
        }
        "demo" => {
            let mailbox = pos.get(1).context("demo 需要 <mailbox_peer_id>")?;
            cmd_demo(&home, mailbox).await
        }
        other => bail!("未知命令: {other}"),
    }
}
