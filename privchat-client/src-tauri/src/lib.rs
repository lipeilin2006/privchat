pub mod layers;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use layers::app::{App, OnionConfig};
use layers::transport::IncomingEnvelope;
use layers::vault::Vault;
use tauri::async_runtime::JoinHandle;
use tauri::{Emitter, Manager, State};
use tokio::sync::{mpsc, Mutex};

/// Android 专用：初始化 `ndk_context`（JavaVM + Application Context）。
///
/// iroh 依赖的 hickory-resolver（读系统 DNS）与 netdev（枚举网卡）都会调用
/// `ndk_context::android_context()`；tauri 不初始化该全局量，导致在
/// `panic = "abort"`（release 配置）下直接 abort 闪退。这里在
/// `JNI_OnLoad` 捕获 JavaVM，再用 `ActivityThread.currentApplication()` 取
/// 应用 Context，显式初始化。
#[cfg(target_os = "android")]
mod android_ctx {
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
    use std::sync::Mutex;

    static JAVA_VM: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
    static INIT_DONE: AtomicBool = AtomicBool::new(false);
    static INIT_LOCK: Mutex<()> = Mutex::new(());

    /// ART 加载动态库时回调；仅捕获 JavaVM 指针。
    #[no_mangle]
    pub unsafe extern "C" fn JNI_OnLoad(
        vm: *mut c_void,
        _reserved: *mut c_void,
    ) -> std::os::raw::c_int {
        JAVA_VM.store(vm, Ordering::SeqCst);
        jni::JNIVersion::V6.into()
    }

    /// 幂等地初始化 `ndk_context`；失败可重试。
    pub fn init() {
        if INIT_DONE.load(Ordering::SeqCst) {
            return;
        }
        let Ok(_guard) = INIT_LOCK.lock() else {
            return;
        };
        if INIT_DONE.load(Ordering::SeqCst) {
            return;
        }
        if init_inner() {
            INIT_DONE.store(true, Ordering::SeqCst);
        }
    }

    fn init_inner() -> bool {
        let jvm_ptr = JAVA_VM.load(Ordering::SeqCst);
        if jvm_ptr.is_null() {
            eprintln!("[privchat] ndk_context: JNI_OnLoad not called yet");
            return false;
        }
        let Ok(vm) = (unsafe { jni::JavaVM::from_raw(jvm_ptr.cast()) }) else {
            eprintln!("[privchat] ndk_context: invalid JavaVM");
            return false;
        };
        let Ok(mut env) = vm.attach_current_thread() else {
            eprintln!("[privchat] ndk_context: attach_current_thread failed");
            return false;
        };
        let Ok(activity_thread) = env.find_class("android/app/ActivityThread") else {
            eprintln!("[privchat] ndk_context: ActivityThread not found");
            return false;
        };
        let Ok(app) = env.call_static_method(
            &activity_thread,
            "currentApplication",
            "()Landroid/app/Application;",
            &[],
        ) else {
            eprintln!("[privchat] ndk_context: currentApplication failed");
            return false;
        };
        let Ok(app_obj) = app.l() else {
            eprintln!("[privchat] ndk_context: application is null");
            return false;
        };
        let Ok(ctx) = env.call_method(
            &app_obj,
            "getApplicationContext",
            "()Landroid/content/Context;",
            &[],
        ) else {
            eprintln!("[privchat] ndk_context: getApplicationContext failed");
            return false;
        };
        let Ok(ctx_obj) = ctx.l() else {
            eprintln!("[privchat] ndk_context: context is null");
            return false;
        };
        let Ok(global) = env.new_global_ref(ctx_obj) else {
            eprintln!("[privchat] ndk_context: new_global_ref failed");
            return false;
        };
        // ndk_context stores this pointer without taking ownership. Keep the
        // GlobalRef alive for the process lifetime; dropping it here leaves a
        // stale JNI reference that crashes Hickory's Android DNS resolver.
        let global = Box::new(global);
        let global_ptr = global.as_raw().cast();
        Box::leak(global);
        unsafe {
            ndk_context::initialize_android_context(jvm_ptr, global_ptr);
        }
        true
    }
}

/// 前端命令的「保险箱状态」：已初始化（首次密码已设置）+ 已解锁（app 已启动）。
#[derive(Clone, Copy, serde::Serialize)]
struct VaultStatus {
    initialized: bool,
    unlocked: bool,
    locked_until_secs: u64,
}

#[derive(serde::Serialize)]
struct AppError {
    code: &'static str,
    message: String,
    retryable: bool,
}

#[derive(serde::Serialize)]
struct Diagnostics {
    app_version: &'static str,
    protocol_version: u8,
    vault_format: u64,
    database_format: &'static str,
    platform: &'static str,
    mailbox_count: usize,
    recent_errors: Vec<String>,
}

#[derive(Default)]
struct UnlockGuard {
    failures: u32,
    locked_until: Option<Instant>,
}

struct AppState {
    /// 落盘数据根目录：setup 钩子里按平台解析后写入。
    data_dir: std::sync::Mutex<Option<PathBuf>>,
    app: Mutex<Option<Arc<App>>>,
    incoming: Mutex<Option<mpsc::UnboundedReceiver<IncomingEnvelope>>>,
    incoming_task: Mutex<Option<JoinHandle<()>>>,
    unlock_guard: std::sync::Mutex<UnlockGuard>,
}

impl AppState {
    /// 取已解析的数据目录（setup 完成后必然已设置）。
    fn data_dir(&self) -> PathBuf {
        self.data_dir
            .lock()
            .unwrap()
            .clone()
            .expect("data_dir not set")
    }

    /// 检查应用层是否已启动；未解锁/未启动时报错，防止在无密钥时误用存储。
    fn require_app(&self) -> Result<Arc<App>, String> {
        self.app
            .try_lock()
            .ok()
            .and_then(|guard| guard.clone())
            .ok_or_else(|| "vault not unlocked".to_string())
    }

    /// 用派生密钥解锁存储并启动应用层。需在 Tauri 事件循环的 setup 中完成，
    /// 以便拿到 app handle 注册入站消息监听。
    async fn start_with_key(
        &self,
        app_handle: tauri::AppHandle,
        key: [u8; 32],
    ) -> Result<(), String> {
        #[cfg(target_os = "android")]
        android_ctx::init();
        let (app, incoming) = App::start(self.data_dir(), key)
            .await
            .map_err(|e| e.to_string())?;
        let app = Arc::new(app);
        *self.app.lock().await = Some(app.clone());
        *self.incoming.lock().await = Some(incoming);

        let mut rx = self
            .incoming
            .lock()
            .await
            .take()
            .expect("incoming receiver set");
        let handle = app_handle.clone();
        let app = app.clone();
        let task = tauri::async_runtime::spawn(async move {
            while let Some(env) = rx.recv().await {
                match app.handle_incoming(env).await {
                    Ok(Some(msg)) => {
                        let _ = handle.emit("chat://message", &msg);
                    }
                    Ok(None) => {} // 队列控制信令，无需上抛前端
                    Err(e) => eprintln!("incoming message failed: {e}"),
                }
            }
        });
        *self.incoming_task.lock().await = Some(task);
        Ok(())
    }
}

fn status(state: &AppState) -> VaultStatus {
    let locked_until_secs = state
        .unlock_guard
        .lock()
        .ok()
        .and_then(|guard| guard.locked_until)
        .map(|until| until.saturating_duration_since(Instant::now()).as_secs())
        .unwrap_or(0);
    VaultStatus {
        initialized: Vault::is_initialized(&state.data_dir()),
        unlocked: state.require_app().is_ok(),
        locked_until_secs,
    }
}

fn user_error(error: impl std::fmt::Display) -> String {
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

#[tauri::command]
async fn vault_status(state: State<'_, AppState>) -> Result<VaultStatus, String> {
    Ok(status(&state))
}

#[tauri::command]
async fn create_vault(
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
        &state.data_dir(),
        &password,
        layers::vault::DEFAULT_ITERATIONS,
    )
    .map_err(user_error)?;
    state.start_with_key(app_handle, vault.db_key()).await?;
    Ok(status(&state))
}

#[tauri::command]
async fn unlock_vault(
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
    let vault = match Vault::unlock(&state.data_dir(), &password) {
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
async fn lock_vault(state: State<'_, AppState>) -> Result<(), String> {
    if let Some(app) = state.app.lock().await.take() {
        app.shutdown().await;
    }
    if let Some(task) = state.incoming_task.lock().await.take() {
        task.abort();
        let _ = task.await;
    }
    *state.incoming.lock().await = None;
    Ok(())
}

#[tauri::command]
async fn export_diagnostics(state: State<'_, AppState>) -> Result<Diagnostics, String> {
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
async fn change_vault_password(
    old_password: String,
    new_password: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    if new_password.is_empty() {
        return Err("新密码不能为空".into());
    }
    Vault::change_password_atomic(
        &state.data_dir(),
        &old_password,
        &new_password,
        layers::vault::DEFAULT_ITERATIONS,
    )
    .map_err(user_error)?;
    Ok(())
}

#[tauri::command]
async fn get_self_ticket(state: State<'_, AppState>) -> Result<String, String> {
    Ok(state.require_app()?.self_ticket().await)
}

#[tauri::command]
async fn delete_pending_identity(
    local_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state
        .require_app()?
        .delete_pending_identity(&local_id)
        .await
        .map_err(user_error)
}

#[tauri::command]
async fn connect_peer(
    ticket: String,
    name: Option<String>,
    state: State<'_, AppState>,
) -> Result<String, String> {
    state
        .require_app()?
        .connect_peer(&ticket, name)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn list_contacts(
    state: State<'_, AppState>,
) -> Result<Vec<layers::app::ContactSummary>, String> {
    Ok(state.require_app()?.list_contacts().await)
}

#[tauri::command]
async fn get_history(
    peer_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<layers::app::ChatMessage>, String> {
    Ok(state.require_app()?.get_history(&peer_id).await)
}

#[tauri::command]
async fn get_draft(peer_id: String, state: State<'_, AppState>) -> Result<String, String> {
    state
        .require_app()?
        .load_draft(&peer_id)
        .map_err(user_error)
}

#[tauri::command]
async fn save_draft(
    peer_id: String,
    text: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state
        .require_app()?
        .save_draft(&peer_id, &text)
        .map_err(user_error)
}

#[tauri::command]
async fn search_messages(
    query: String,
    limit: Option<usize>,
    state: State<'_, AppState>,
) -> Result<Vec<(String, layers::app::ChatMessage)>, String> {
    state
        .require_app()?
        .search_messages(&query, limit.unwrap_or(100).min(500))
        .map_err(user_error)
}

#[tauri::command]
async fn send_message(
    peer_id: String,
    text: String,
    state: State<'_, AppState>,
) -> Result<layers::app::ChatMessage, String> {
    state
        .require_app()?
        .send_message(&peer_id, &text)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn delete_contact(peer_id: String, state: State<'_, AppState>) -> Result<(), String> {
    state
        .require_app()?
        .delete_contact(&peer_id)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn rename_contact(
    peer_id: String,
    name: String,
    state: State<'_, AppState>,
) -> Result<layers::app::ContactSummary, String> {
    state
        .require_app()?
        .rename_contact(&peer_id, &name)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_onion_config(state: State<'_, AppState>) -> Result<OnionConfig, String> {
    Ok(state.require_app()?.get_onion_config().await)
}

#[tauri::command]
async fn set_onion_config(config: OnionConfig, state: State<'_, AppState>) -> Result<(), String> {
    state
        .require_app()?
        .set_onion_config(config)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_mailbox_peers(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    Ok(state.require_app()?.get_mailbox_peers().await)
}

#[tauri::command]
async fn ping_mailbox(peer_id: String, state: State<'_, AppState>) -> Result<u64, String> {
    state
        .require_app()?
        .ping_mailbox(&peer_id)
        .await
        .map_err(user_error)
}

#[tauri::command]
async fn add_mailbox_peer(peer_id: String, state: State<'_, AppState>) -> Result<(), String> {
    state
        .require_app()?
        .add_mailbox_peer(&peer_id)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn remove_mailbox_peer(peer_id: String, state: State<'_, AppState>) -> Result<(), String> {
    state
        .require_app()?
        .remove_mailbox_peer(&peer_id)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_mailbox_write_count(state: State<'_, AppState>) -> Result<usize, String> {
    Ok(state.require_app()?.get_mailbox_write_count().await)
}

#[tauri::command]
async fn get_auto_lock_minutes(state: State<'_, AppState>) -> Result<u64, String> {
    state
        .require_app()?
        .get_auto_lock_minutes()
        .map_err(user_error)
}

#[tauri::command]
async fn set_auto_lock_minutes(minutes: u64, state: State<'_, AppState>) -> Result<(), String> {
    state
        .require_app()?
        .set_auto_lock_minutes(minutes)
        .map_err(user_error)
}

#[tauri::command]
async fn set_mailbox_write_count(count: usize, state: State<'_, AppState>) -> Result<(), String> {
    state
        .require_app()?
        .set_mailbox_write_count(count)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn exit_app(app_handle: tauri::AppHandle) {
    app_handle.exit(0);
}

/// 解析落盘数据根目录（vault.json / privchat.db 实际存放位置）。
/// 优先级：
/// 1. `PRIVCHAT_DATA_DIR` 环境变量（显式覆盖，桌面/移动通用）；
/// 2. 移动端：tauri 的 app_data_dir（安卓 = `/data/user/0/<包名>/files`，
///    持久且受系统管理，可写），数据存其下的 `data` 子目录；
/// 3. 桌面端：可执行文件所在目录（保持原有行为，兜底 temp），
///    数据存其下的 `data` 子目录。
fn resolve_data_dir(app: &tauri::AppHandle) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Ok(dir) = std::env::var("PRIVCHAT_DATA_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let base = {
        #[cfg(mobile)]
        {
            app.path().app_data_dir()?
        }
        #[cfg(not(mobile))]
        {
            let _ = app; // 桌面端无需 AppHandle，仅移动端用
            std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(PathBuf::from))
                .unwrap_or_else(|| std::env::temp_dir().join("privchat-client"))
        }
    };
    Ok(base.join("data"))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // 提前初始化 ndk_context，避免 iroh 在后台线程 panic（release 为 panic=abort）。
    #[cfg(target_os = "android")]
    android_ctx::init();
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_app::init());
    // barcode-scanner 仅在移动端（Android/iOS）提供真实实现；桌面端该 crate 为空。
    #[cfg(mobile)]
    let builder = builder.plugin(tauri_plugin_barcode_scanner::init());
    builder
        .manage(AppState {
            data_dir: std::sync::Mutex::new(None),
            app: Mutex::new(None),
            incoming: Mutex::new(None),
            incoming_task: Mutex::new(None),
            unlock_guard: std::sync::Mutex::new(UnlockGuard::default()),
        })
        .setup(|app| {
            let dir = resolve_data_dir(app.handle())?;
            *app.state::<AppState>().data_dir.lock().unwrap() = Some(dir);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            vault_status,
            create_vault,
            unlock_vault,
            lock_vault,
            export_diagnostics,
            change_vault_password,
            get_self_ticket,
            delete_pending_identity,
            connect_peer,
            send_message,
            list_contacts,
            get_history,
            get_draft,
            save_draft,
            search_messages,
            delete_contact,
            rename_contact,
            get_mailbox_peers,
            get_onion_config,
            set_onion_config,
            ping_mailbox,
            add_mailbox_peer,
            remove_mailbox_peer,
            get_mailbox_write_count,
            get_auto_lock_minutes,
            set_auto_lock_minutes,
            set_mailbox_write_count,
            exit_app
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|_app_handle, _event| {
            // 默认行为：所有窗口关闭后应用退出。不要在这里调用 app_handle.exit(0)——
            // 主线程调用 exit 会重入 ExitRequested/Exit 事件，导致进程无法干净终止。
        });
}
