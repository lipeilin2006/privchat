//! Tauri 命令层：前端能调用的全部入口。

use std::time::{Duration, Instant};

use crate::layers::app::OnionConfig;
use tauri::State;

use crate::layers::vault::Vault;
use crate::state::{status, AppState, VaultStatus};

#[derive(serde::Serialize)]
pub(crate) struct AppError {
    code: &'static str,
    message: String,
    retryable: bool,
}

#[derive(serde::Serialize)]
pub(crate) struct Diagnostics {
    app_version: &'static str,
    protocol_version: u8,
    vault_format: u64,
    database_format: &'static str,
    platform: &'static str,
    mailbox_count: usize,
    recent_errors: Vec<String>,
}

#[tauri::command]
pub(crate) async fn vault_status(state: State<'_, AppState>) -> Result<VaultStatus, String> {
    crate::diag::trace("cmd vault_status");
    Ok(status(&state))
}

#[tauri::command]
pub(crate) async fn create_vault(
    password: String,
    state: State<'_, AppState>,
    app_handle: tauri::AppHandle,
) -> Result<VaultStatus, String> {
    if status(&state).initialized {
        return Err("vault already initialized".into());
    }
    if password.is_empty() {
        return Err("密码不能为空".into());
    }
    let vault = Vault::create(
        &state.data_dir()?,
        &password,
        crate::layers::vault::DEFAULT_ITERATIONS,
    )
    .map_err(user_error)?;
    state.start_with_key(app_handle, vault.db_key()).await?;
    Ok(status(&state))
}

#[tauri::command]
pub(crate) async fn unlock_vault(
    password: String,
    state: State<'_, AppState>,
    app_handle: tauri::AppHandle,
) -> Result<VaultStatus, String> {
    {
        let guard = state
            .unlock_guard
            .lock()
            .map_err(|_| "操作失败".to_string())?;
        if let Some(until) = guard.locked_until {
            if until > Instant::now() {
                return Err(format!(
                    "登录暂时锁定，请 {} 秒后重试",
                    until.duration_since(Instant::now()).as_secs()
                ));
            }
        }
    }
    if !status(&state).initialized {
        return Err("vault not initialized".into());
    }
    let vault = match Vault::unlock(&state.data_dir()?, &password) {
        Ok(vault) => {
            if let Ok(mut guard) = state.unlock_guard.lock() {
                guard.failures = 0;
                guard.locked_until = None;
            }
            vault
        }
        Err(error) => {
            if let Ok(mut guard) = state.unlock_guard.lock() {
                guard.failures = guard.failures.saturating_add(1);
                if guard.failures >= 5 {
                    let seconds = 2u64.pow((guard.failures - 5).min(5));
                    guard.locked_until = Some(Instant::now() + Duration::from_secs(seconds));
                }
            }
            return Err(user_error(error));
        }
    };
    state
        .start_with_key(app_handle, vault.db_key())
        .await
        .map_err(user_error)?;
    Ok(status(&state))
}

#[tauri::command]
pub(crate) async fn lock_vault(state: State<'_, AppState>) -> Result<(), String> {
    if let Some(app) = state.app.lock().await.take() {
        app.shutdown().await;
    }
    if let Some(task) = state.poll_task.lock().await.take() {
        task.abort();
    }
    Ok(())
}

#[tauri::command]
pub(crate) async fn export_diagnostics(state: State<'_, AppState>) -> Result<Diagnostics, String> {
    let app = state.require_app()?;
    Ok(Diagnostics {
        app_version: env!("CARGO_PKG_VERSION"),
        protocol_version: 4,
        vault_format: 2,
        database_format: "sqlcipher-current",
        platform: std::env::consts::OS,
        mailbox_count: app.get_mailbox_peers().await.len(),
        recent_errors: Vec::new(),
    })
}

#[tauri::command]
pub(crate) async fn change_vault_password(
    old_password: String,
    new_password: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    if new_password.is_empty() {
        return Err("新密码不能为空".into());
    }
    Vault::change_password_atomic(
        &state.data_dir()?,
        &old_password,
        &new_password,
        crate::layers::vault::DEFAULT_ITERATIONS,
    )
    .map_err(user_error)?;
    Ok(())
}

#[tauri::command]
pub(crate) async fn get_onion_config(state: State<'_, AppState>) -> Result<OnionConfig, String> {
    Ok(state.require_app()?.get_onion_config().await)
}

#[tauri::command]
pub(crate) async fn set_onion_config(
    config: OnionConfig,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state
        .require_app()?
        .set_onion_config(config)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub(crate) async fn get_mailbox_peers(
    state: State<'_, AppState>,
) -> Result<Vec<crate::layers::store::MailboxPeer>, String> {
    Ok(state.require_app()?.get_mailbox_peers().await)
}

/// 一次给所有信箱测速（并发），返回各自的往返毫秒数。
/// 信箱选路权重（0..=1）：0 = 只看优先级，1 = 只看延迟。
#[tauri::command]
pub(crate) async fn get_mailbox_weight(state: State<'_, AppState>) -> Result<f64, String> {
    Ok(state.require_app()?.get_mailbox_weight().await)
}

#[tauri::command]
pub(crate) async fn set_mailbox_weight(
    weight: f64,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state
        .require_app()?
        .set_mailbox_weight(weight)
        .await
        .map_err(|e| e.to_string())
}

/// 最近一次信箱测速的缓存（peer_id → 毫秒）。
#[tauri::command]
pub(crate) async fn mailbox_latency(
    state: State<'_, AppState>,
) -> Result<std::collections::HashMap<String, u64>, String> {
    Ok(state.require_app()?.get_mailbox_latency().await)
}

/// 测中继延迟（连一下就走，不真发请求）。
#[tauri::command]
pub(crate) async fn test_onion_relays(
    state: State<'_, AppState>,
) -> Result<Vec<crate::layers::app::RelayPing>, String> {
    Ok(state.require_app()?.test_relays().await)
}

/// 最近一次中继测速的缓存（peer_id → 毫秒）。
#[tauri::command]
pub(crate) async fn onion_relay_latency(
    state: State<'_, AppState>,
) -> Result<std::collections::HashMap<String, u64>, String> {
    Ok(state.require_app()?.get_relay_latency().await)
}

#[tauri::command]
pub(crate) async fn ping_mailboxes(
    state: State<'_, AppState>,
) -> Result<Vec<crate::layers::app::MailboxPing>, String> {
    let app = state.require_app()?;
    let peers: Vec<String> = app
        .get_mailbox_peers()
        .await
        .into_iter()
        .map(|peer| peer.peer_id)
        .collect();
    Ok(app.ping_mailboxes(&peers).await)
}

#[tauri::command]
pub(crate) async fn ping_mailbox(
    peer_id: String,
    state: State<'_, AppState>,
) -> Result<u64, String> {
    state
        .require_app()?
        .ping_mailbox(&peer_id)
        .await
        .map_err(user_error)
}

#[tauri::command]
pub(crate) async fn add_mailbox_peer(
    peer_id: String,
    priority: Option<i64>,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state
        .require_app()?
        .add_mailbox_peer(&peer_id, priority.unwrap_or(0))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub(crate) async fn set_mailbox_priority(
    peer_id: String,
    priority: i64,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state
        .require_app()?
        .set_mailbox_priority(&peer_id, priority)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub(crate) async fn remove_mailbox_peer(
    peer_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state
        .require_app()?
        .remove_mailbox_peer(&peer_id)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub(crate) async fn get_auto_lock_minutes(state: State<'_, AppState>) -> Result<u64, String> {
    state
        .require_app()?
        .get_auto_lock_minutes()
        .map_err(user_error)
}

#[tauri::command]
pub(crate) async fn set_auto_lock_minutes(
    minutes: u64,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state
        .require_app()?
        .set_auto_lock_minutes(minutes)
        .map_err(user_error)
}

/// 前端用的连接摘要。
#[derive(serde::Serialize)]
pub(crate) struct ConnectionSummary {
    conn_id: String,
    name: Option<String>,
    state: String,
}

/// 前端用的连接消息。
#[derive(serde::Serialize)]
pub(crate) struct ConnectionMessage {
    id: String,
    from: String,
    text: String,
    time: u64,
    /// "text" / "file"
    kind: String,
    name: Option<String>,
    mime: Option<String>,
    /// 附件内容（base64），只有 kind=file 才有。
    data: Option<String>,
}

/// 新协议：生成邀请（同时在该 mailbox 上创建接收队列）。
#[tauri::command]
pub(crate) async fn create_connection(
    mailbox: Option<String>,
    state: State<'_, AppState>,
) -> Result<(String, String), String> {
    state
        .require_app()?
        .create_connection(mailbox.as_deref())
        .await
        .map_err(|e| e.to_string())
}

/// 新协议：扫到对方邀请后配对。
#[tauri::command]
pub(crate) async fn accept_connection(
    conn_id: String,
    invite: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state
        .require_app()?
        .accept_connection(&conn_id, &invite)
        .await
        .map_err(|e| e.to_string())
}

/// 删除连接：本地状态 + 节点队列一起清掉。
#[tauri::command]
pub(crate) async fn delete_connection(
    conn_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state
        .require_app()?
        .delete_connection(&conn_id)
        .await
        .map_err(|e| e.to_string())
}

/// 手动轮换入站队列（换一条队列，可以换到另一台信箱）。
#[tauri::command]
pub(crate) async fn rotate_connection(
    conn_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state
        .require_app()?
        .rotate_connection(&conn_id)
        .await
        .map_err(|e| e.to_string())
}

/// 发附件（base64 传入，≤2MB）。
#[tauri::command]
pub(crate) async fn send_file(
    conn_id: String,
    name: String,
    mime: String,
    data: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data.as_bytes())
        .map_err(|_| "附件内容不是合法 base64".to_string())?;
    state
        .require_app()?
        .send_file(&conn_id, &name, &mime, bytes)
        .await
        .map_err(|e| e.to_string())
}

/// 新协议：发消息。
#[tauri::command]
pub(crate) async fn send_on_connection(
    conn_id: String,
    text: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state
        .require_app()?
        .send_on_connection(&conn_id, &text)
        .await
        .map_err(|e| e.to_string())
}

/// 新协议：连接列表。
#[tauri::command]
pub(crate) async fn list_connections(
    state: State<'_, AppState>,
) -> Result<Vec<ConnectionSummary>, String> {
    let app = state.require_app()?;
    Ok(app
        .list_connections()
        .await
        .into_iter()
        .map(|(conn_id, name, state)| ConnectionSummary {
            conn_id,
            name,
            state: format!("{state:?}").to_lowercase(),
        })
        .collect())
}

/// 新协议：某连接的历史消息。
#[tauri::command]
pub(crate) async fn connection_history(
    conn_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<ConnectionMessage>, String> {
    let app = state.require_app()?;
    Ok(app
        .connection_history(&conn_id)
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|m| {
            use base64::Engine;
            ConnectionMessage {
                id: m.msg_id,
                from: m.sender,
                text: m.text,
                time: m.time,
                kind: m.kind,
                name: m.name,
                mime: m.mime,
                data: m
                    .data
                    .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes)),
            }
        })
        .collect())
}

/// 新协议：给连接改备注（只是显示名）。
#[tauri::command]
pub(crate) async fn rename_connection(
    conn_id: String,
    name: Option<String>,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state
        .require_app()?
        .rename_connection(&conn_id, name.as_deref())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub(crate) fn exit_app(app_handle: tauri::AppHandle) {
    crate::diag::trace("cmd exit_app");
    app_handle.exit(0);
}

pub(crate) fn user_error(error: impl std::fmt::Display) -> String {
    let text = error.to_string().to_lowercase();
    let (code, message, retryable) = if text.contains("wrong password") {
        ("wrong_password", "密码错误，请重试", true)
    } else if text.contains("cannot open database") || text.contains("database") {
        ("database_corrupt", "本地数据库损坏或无法解密", false)
    } else if text.contains("incompatible") || text.contains("version") {
        (
            "incompatible_data",
            "数据版本不兼容，请创建新的数据目录",
            false,
        )
    } else if text.contains("connect") || text.contains("relay") || text.contains("network") {
        ("network_unavailable", "网络不可用，请检查网络连接", true)
    } else if text.contains("mailbox") {
        ("mailbox_unavailable", "Mailbox 节点不可达", true)
    } else if text.contains("identity") || text.contains("secret") {
        (
            "identity_recovery_failed",
            "身份恢复失败，请检查本地数据",
            false,
        )
    } else {
        ("operation_failed", "操作失败，请稍后重试", true)
    };
    serde_json::to_string(&AppError {
        code,
        message: message.into(),
        retryable,
    })
    .unwrap_or_else(|_| message.into())
}
