//! PrivChat 洋葱中继节点。
//!
//! 只做两件事：剥掉自己那一层、把剩下的包转给下一跳。
//! 不落库、不解析内容、不存任何消息——存储是 `privchat-mailbox` 的事。
//!
//! 配置：`<data_dir>/config.json`
//! ```json
//! { "bind": "0.0.0.0:8444", "onion_peers": [] }
//! ```

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Result};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, SecretKey};

use privchat_common::MailboxResponse;
use privchat_onion::{peel, ONION_ALPN, PACKET_MAX, RESPONSE_MAX};

const CONFIG_FILE: &str = "config.json";

/// 中继节点配置。环境变量只用来临时覆盖。
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct RelayConfig {
    /// 固定监听地址，例如 "0.0.0.0:8444"；不写则随机端口。
    #[serde(default)]
    bind: Option<String>,
    /// 允许转发的下一跳白名单；空 = 不限制。
    #[serde(default)]
    onion_peers: Option<Vec<String>>,
}

fn is_peer_id(id: &str) -> bool {
    id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit())
}

fn env_string(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn load_config(data_dir: &std::path::Path) -> RelayConfig {
    let path = data_dir.join(CONFIG_FILE);
    let Ok(bytes) = std::fs::read(&path) else {
        return RelayConfig::default();
    };
    match serde_json::from_slice::<RelayConfig>(&bytes) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("[relay] config.json 解析失败，按默认值启动: {e}");
            RelayConfig::default()
        }
    }
}

fn ensure_config(data_dir: &std::path::Path, cfg: &RelayConfig) -> Result<()> {
    let path = data_dir.join(CONFIG_FILE);
    if path.exists() {
        return Ok(());
    }
    std::fs::write(&path, serde_json::to_string_pretty(cfg)?)?;
    eprintln!("[relay] wrote {}", path.display());
    Ok(())
}

fn short_id(id: &str) -> &str {
    &id[..id.len().min(12)]
}

/// 中继处理器：剥离一层后转发；自己是终点时明确拒绝（那是信箱的活）。
#[derive(Debug, Clone)]
struct RelayHandler {
    secret: SecretKey,
    endpoint: Endpoint,
    allow: Option<Vec<String>>,
}

impl RelayHandler {
    async fn respond(
        &self,
        send: &mut iroh::endpoint::SendStream,
        result: Result<Vec<u8>, String>,
    ) {
        let bytes = match result {
            Ok(raw) => raw,
            Err(error) => serde_json::to_vec(&MailboxResponse {
                ok: false,
                error: Some(error),
                messages: None,
            })
            .unwrap_or_default(),
        };
        let _ = send.write_all(&bytes).await;
    }
}

impl ProtocolHandler for RelayHandler {
    async fn accept(&self, connection: iroh::endpoint::Connection) -> Result<(), AcceptError> {
        let remote = connection.remote_id().to_string();
        let (mut send, mut recv) = match connection.accept_bi().await {
            Ok(bi) => bi,
            Err(_) => return Ok(()),
        };
        let packet = match recv.read_to_end(PACKET_MAX).await {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("[relay] read failed: {error:#}");
                return Ok(());
            }
        };

        let result = match peel(&self.secret, &packet) {
            Ok((Some(next), inner)) => {
                if let Some(allow) = &self.allow {
                    if !allow.iter().any(|p| p == &next) {
                        self.respond(&mut send, Err("next hop is not in the allowlist".into()))
                            .await;
                        let _ = send.finish();
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        return Ok(());
                    }
                }
                eprintln!(
                    "[relay] from {}: forwarding {}B to {}",
                    short_id(&remote),
                    inner.len(),
                    short_id(&next)
                );
                forward(&self.endpoint, &next, inner).await
            }
            Ok((None, _)) => Err("this node is relay-only: refusing terminal delivery".into()),
            Err(error) => Err(format!("onion peel failed: {error:#}")),
        };
        self.respond(&mut send, result).await;
        let _ = send.finish();
        // 给对端一点时间读走最后一段响应再关连接。
        tokio::time::sleep(Duration::from_millis(500)).await;
        Ok(())
    }
}

/// 把剩余洋葱包转给下一跳；响应原样回传（中继不解析内容）。
async fn forward(endpoint: &Endpoint, next: &str, inner: Vec<u8>) -> Result<Vec<u8>, String> {
    let id: iroh::EndpointId = next
        .parse()
        .map_err(|_| format!("invalid next hop: {next}"))?;
    let conn = tokio::time::timeout(
        Duration::from_secs(90),
        endpoint.connect(iroh::EndpointAddr::new(id), ONION_ALPN),
    )
    .await
    .map_err(|_| format!("connect {next} timed out"))?
    .map_err(|e| format!("connect {next} failed: {e}"))?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| format!("open stream to {next} failed: {e}"))?;
    send.write_all(&inner)
        .await
        .map_err(|e| format!("write to {next} failed: {e}"))?;
    send.finish()
        .map_err(|e| format!("finish to {next} failed: {e}"))?;
    let bytes = tokio::time::timeout(Duration::from_secs(90), recv.read_to_end(RESPONSE_MAX))
        .await
        .map_err(|_| format!("waiting {next} response timed out"))?
        .map_err(|e| format!("reading {next} response failed: {e}"))?;
    Ok(bytes)
}

#[tokio::main]
async fn main() -> Result<()> {
    let data_dir = env_string("PRIVCHAT_RELAY_DATA_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(PathBuf::from))
        })
        .unwrap_or_else(|| std::env::temp_dir().join("privchat-relay"));
    std::fs::create_dir_all(&data_dir)?;

    let secret_path = data_dir.join("secret.key");
    let secret = if let Ok(bytes) = std::fs::read(&secret_path) {
        SecretKey::try_from(bytes.as_slice())?
    } else {
        let key = SecretKey::generate();
        std::fs::write(&secret_path, key.to_bytes())?;
        key
    };

    let file_cfg = load_config(&data_dir);
    let bind = env_string("PRIVCHAT_RELAY_BIND").or(file_cfg.bind.clone());
    let allow = match env_string("PRIVCHAT_RELAY_ONION_PEERS") {
        Some(raw) => Some(
            raw.split(',')
                .map(str::trim)
                .filter(|p| is_peer_id(p))
                .map(str::to_string)
                .collect::<Vec<_>>(),
        ),
        None => file_cfg.onion_peers.clone(),
    }
    .filter(|list: &Vec<String>| !list.is_empty());

    ensure_config(
        &data_dir,
        &RelayConfig {
            bind: bind.clone(),
            onion_peers: allow.clone(),
        },
    )?;

    let mut builder = Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(secret.clone())
        .alpns(vec![ONION_ALPN.to_vec()]);
    if let Some(bind) = &bind {
        let addr: std::net::SocketAddr = bind
            .parse()
            .map_err(|e| anyhow!("config.json 的 bind 不是合法地址 {bind}: {e}"))?;
        builder = builder
            .bind_addr(addr)
            .map_err(|e| anyhow!("bind_addr {addr} 失败: {e}"))?;
    }
    let endpoint = builder.bind().await?;

    let _router = Router::builder(endpoint.clone())
        .accept(
            ONION_ALPN,
            RelayHandler {
                secret,
                endpoint: endpoint.clone(),
                allow,
            },
        )
        .spawn();

    let _ = tokio::time::timeout(Duration::from_secs(8), endpoint.online()).await;

    println!("PrivChat Relay online");
    println!("  peer_id : {}", endpoint.id());
    println!("  data_dir: {}", data_dir.display());
    if let Some(bind) = &bind {
        println!("  bind    : {bind}");
    }

    std::future::pending::<()>().await;
    Ok(())
}
