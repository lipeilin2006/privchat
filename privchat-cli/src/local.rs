//! 本地状态命令：建身份、看身份、加联系人、导出状态。

use super::*;

pub(crate) fn cmd_derive(home: &Path, name: &str, label: &str) -> Result<()> {
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

pub(crate) async fn cmd_init(home: &Path, name: &str) -> Result<()> {
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

pub(crate) fn cmd_id(home: &Path, name: &str) -> Result<()> {
    let secret = load_secret(home, name)?;
    println!(
        "{}",
        privchat_client_lib::layers::crypto::encode_invite(&secret, &cli_spk_pub(&secret), None)
    );
    Ok(())
}

pub(crate) fn cmd_ls(home: &Path) -> Result<()> {
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

pub(crate) fn cmd_contact(
    home: &Path,
    name: &str,
    label_or_peer: &str,
    peer: Option<&str>,
) -> Result<()> {
    load_secret(home, name)?;
    // 邀请串 → (peer_id, SPK)；兼容直接给 peer_id（此时只能当响应方）。
    let parse_one = |raw: &str| -> Result<(String, Option<String>)> {
        if raw.starts_with("pc1:") {
            let (peer, spk, _ticket) = privchat_client_lib::layers::crypto::parse_invite(raw)?;
            Ok((peer, Some(hex_of(&spk))))
        } else {
            Ok((raw.to_string(), None))
        }
    };
    let (label, peer_id, spk) = match peer {
        Some(p) => {
            let (peer_id, spk) = parse_one(p)?;
            (label_or_peer.to_string(), peer_id, spk)
        }
        None => {
            let (peer_id, spk) = parse_one(label_or_peer)?;
            let label = if peer_id.len() > 8 {
                peer_id[..8].to_string()
            } else {
                peer_id.clone()
            };
            (label, peer_id, spk)
        }
    };
    if peer_id.len() != 64 {
        bail!("peer id 应为 64 位十六进制");
    }
    let path = home.join(format!("{name}.contacts"));
    let mut existing = fs::read_to_string(&path).unwrap_or_default();
    let already = contacts(home, name)?
        .iter()
        .any(|(l, p, _)| l == &label || p == &peer_id);
    if !already {
        if !existing.ends_with('\n') && !existing.is_empty() {
            existing.push('\n');
        }
        match &spk {
            Some(spk) => existing.push_str(&format!("{label} {peer_id} {spk}\n")),
            None => existing.push_str(&format!("{label} {peer_id}\n")),
        }
        fs::write(&path, existing)?;
    }
    println!("contact added: {name} {label} -> {peer_id}");
    Ok(())
}

/// 校验状态文件：magic / 版本 / 归属身份是否匹配（P3 的可观测入口）。
pub(crate) fn cmd_state(home: &Path, name: &str, label: &str) -> Result<()> {
    let (label, peer, _spk) = resolve_contact(home, name, label)?;
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
