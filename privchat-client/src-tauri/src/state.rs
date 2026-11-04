//! 应用状态：保险箱解锁状态、已启动的 App、后台任务句柄。

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use crate::layers::app::App;
use crate::layers::vault::Vault;
use tauri::async_runtime::JoinHandle;
use tauri::Emitter;
use tokio::sync::Mutex;

/// 前端命令的「保险箱状态」：已初始化（首次密码已设置）+ 已解锁（app 已启动）。
#[derive(Clone, Copy, serde::Serialize)]
pub(crate) struct VaultStatus {
    pub(crate) initialized: bool,
    pub(crate) unlocked: bool,
    pub(crate) locked_until_secs: u64,
}

#[derive(Default)]
pub(crate) struct UnlockGuard {
    pub(crate) failures: u32,
    pub(crate) locked_until: Option<Instant>,
}

pub(crate) struct AppState {
    /// 落盘数据根目录：setup 钩子里按平台解析后写入。
    pub(crate) data_dir: std::sync::Mutex<Option<PathBuf>>,
    pub(crate) app: Mutex<Option<Arc<App>>>,
    pub(crate) poll_task: Mutex<Option<JoinHandle<()>>>,
    pub(crate) unlock_guard: std::sync::Mutex<UnlockGuard>,
}

impl AppState {
    /// 取已解析的数据目录；setup 还没跑完时返回错误而不是 panic
    /// （安卓上 WebView 的 JS 有可能比 setup 先跑起来）。
    pub(crate) fn data_dir(&self) -> Result<PathBuf, String> {
        self.data_dir
            .lock()
            .map_err(|_| "应用状态异常".to_string())?
            .clone()
            .ok_or_else(|| "应用还没准备好，请重试".to_string())
    }

    /// 检查应用层是否已启动；未解锁/未启动时报错，防止在无密钥时误用存储。
    pub(crate) fn require_app(&self) -> Result<Arc<App>, String> {
        self.app
            .try_lock()
            .ok()
            .and_then(|guard| guard.clone())
            .ok_or_else(|| "vault not unlocked".to_string())
    }

    /// 用派生密钥解锁存储并启动应用层，同时启动连接轮询任务。
    pub(crate) async fn start_with_key(
        &self,
        app_handle: tauri::AppHandle,
        key: [u8; 32],
    ) -> Result<(), String> {
        #[cfg(target_os = "android")]
        crate::android_ctx::init();
        crate::diag::trace("app: start_with_key");
        let app = Arc::new(
            App::start(self.data_dir()?, key)
                .await
                .map_err(|e| e.to_string())?,
        );
        *self.app.lock().await = Some(app.clone());

        // 每 3 秒拉一次已建立的连接，新消息通过事件上抛前端。
        let handle = app_handle.clone();
        let poll_app = app.clone();
        let task = tauri::async_runtime::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3));
            loop {
                ticker.tick().await;
                for (conn_id, text) in poll_app.poll_all_connections().await {
                    let _ = handle.emit(
                        "connection://message",
                        &serde_json::json!({"conn_id": conn_id, "text": text}),
                    );
                }
            }
        });
        *self.poll_task.lock().await = Some(task);
        Ok(())
    }
}

pub(crate) fn status(state: &AppState) -> VaultStatus {
    let locked_until_secs = state
        .unlock_guard
        .lock()
        .ok()
        .and_then(|guard| guard.locked_until)
        .map(|until| until.saturating_duration_since(Instant::now()).as_secs())
        .unwrap_or(0);
    VaultStatus {
        initialized: state
            .data_dir()
            .map(|dir| Vault::is_initialized(&dir))
            .unwrap_or(false),
        unlocked: state.require_app().is_ok(),
        locked_until_secs,
    }
}
