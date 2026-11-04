//! PrivChat 桌面/移动客户端入口：Tauri 应用装配。

pub mod commands;
pub mod diag;
pub mod layers;
pub mod state;

use std::path::PathBuf;

use crate::commands::*;
use crate::state::{AppState, UnlockGuard};
use tauri::Manager;
use tokio::sync::Mutex;

#[cfg(target_os = "android")]
pub(crate) mod android_ctx {
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
    diag::install_panic_hook();
    diag::trace("run() enter");
    // 提前初始化 ndk_context，避免 iroh 在后台线程 panic（release 为 panic=abort）。
    #[cfg(target_os = "android")]
    {
        android_ctx::init();
        diag::trace("ndk_context init");
    }
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
            poll_task: Mutex::new(None),
            unlock_guard: std::sync::Mutex::new(UnlockGuard::default()),
        })
        .setup(|app| {
            diag::trace("setup: resolve data dir");
            let dir = resolve_data_dir(app.handle())?;
            diag::set_dir(dir.clone());
            diag::trace(&format!("setup: data_dir={}", dir.display()));
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
            get_mailbox_peers,
            get_onion_config,
            set_onion_config,
            ping_mailbox,
            add_mailbox_peer,
            remove_mailbox_peer,
            get_auto_lock_minutes,
            set_auto_lock_minutes,
            create_connection,
            accept_connection,
            send_on_connection,
            poll_connection,
            list_connections,
            connection_history,
            rename_connection,
            exit_app,
            boot_prev_log,
            boot_current_log,
            boot_trace,
            boot_prev_log_clear
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|_app_handle, _event| {
            // 默认行为：所有窗口关闭后应用退出。不要在这里调用 app_handle.exit(0)——
            // 主线程调用 exit 会重入 ExitRequested/Exit 事件，导致进程无法干净终止。
        });
}
