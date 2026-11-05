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
    /// `getApplicationContext()` 的全局引用，进程期间一直有效。
    static APP_CTX: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
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

    /// 幂等地拿到 application context（给 files_dir / toast 用）。
    /// 不初始化 ndk_context——那个归 tao。
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
        APP_CTX.store(global_ptr, Ordering::SeqCst);
        // 注意：这里**不能**调 ndk_context::initialize_android_context。
        // tao 在事件循环里自己会调，而它内部是 assert!(previous.is_none())，
        // 谁先调第二个人就 panic —— 安卓上一启动就闪退就是这么来的。
        // tao 初始化之后，iroh 的 DNS 直接用 ndk_context 就好了。
        true
    }

    /// 应用私有文件目录（`/data/user/0/<包名>/files`）。
    /// Tauri 的 path 插件拿不到时用它兜底。
    pub fn files_dir() -> Option<std::path::PathBuf> {
        let jvm_ptr = JAVA_VM.load(Ordering::SeqCst);
        let ctx_ptr = APP_CTX.load(Ordering::SeqCst);
        if jvm_ptr.is_null() || ctx_ptr.is_null() {
            return None;
        }
        let Ok(vm) = (unsafe { jni::JavaVM::from_raw(jvm_ptr.cast()) }) else {
            return None;
        };
        let Ok(mut env) = vm.attach_current_thread() else {
            return None;
        };
        let ctx = unsafe { jni::objects::JObject::from_raw(ctx_ptr.cast()) };
        let file = env
            .call_method(&ctx, "getFilesDir", "()Ljava/io/File;", &[])
            .ok()?
            .l()
            .ok()?;
        let path = env
            .call_method(&file, "getAbsolutePath", "()Ljava/lang/String;", &[])
            .ok()?
            .l()
            .ok()?;
        let text: String = env
            .get_string(&jni::objects::JString::from(path))
            .ok()?
            .into();
        Some(std::path::PathBuf::from(text))
    }

    /// 用系统查看器打开一个文件（FileProvider 给临时读权限）。
    #[cfg(target_os = "android")]
    pub fn open_file(path: &str, mime: &str) -> bool {
        let jvm_ptr = JAVA_VM.load(Ordering::SeqCst);
        let ctx_ptr = APP_CTX.load(Ordering::SeqCst);
        if jvm_ptr.is_null() || ctx_ptr.is_null() {
            return false;
        }
        let Ok(vm) = (unsafe { jni::JavaVM::from_raw(jvm_ptr.cast()) }) else {
            return false;
        };
        let Ok(mut env) = vm.attach_current_thread() else {
            return false;
        };
        let ctx = unsafe { jni::objects::JObject::from_raw(ctx_ptr.cast()) };

        let Ok(package) = env
            .call_method(&ctx, "getPackageName", "()Ljava/lang/String;", &[])
            .and_then(|value| value.l())
        else {
            return false;
        };
        let package_jstring = jni::objects::JString::from(package);
        let Ok(package) = env.get_string(&package_jstring) else {
            return false;
        };
        let package = package.to_string_lossy().into_owned();
        let authority = format!("{package}.fileprovider");
        let (Ok(authority_j), Ok(path_j), Ok(mime_j)) = (
            env.new_string(authority),
            env.new_string(path),
            env.new_string(mime),
        ) else {
            return false;
        };

        let Ok(file_class) = env.find_class("java/io/File") else {
            return false;
        };
        let Ok(file) = env.new_object(
            file_class,
            "(Ljava/lang/String;)V",
            &[jni::objects::JValue::Object(&path_j)],
        ) else {
            return false;
        };
        let Ok(provider) = env.find_class("androidx/core/content/FileProvider") else {
            return false;
        };
        let uri = env
            .call_static_method(
                provider,
                "getUriForFile",
                "(Landroid/content/Context;Ljava/lang/String;Ljava/io/File;)Landroid/net/Uri;",
                &[
                    jni::objects::JValue::Object(&ctx),
                    jni::objects::JValue::Object(&authority_j),
                    jni::objects::JValue::Object(&file),
                ],
            )
            .ok()
            .and_then(|value| value.l().ok());
        let Some(uri) = uri else {
            return false;
        };

        let Ok(intent_class) = env.find_class("android/content/Intent") else {
            return false;
        };
        let Ok(action) = env.new_string("android.intent.action.VIEW") else {
            return false;
        };
        let Ok(intent) = env.new_object(
            intent_class,
            "(Ljava/lang/String;)V",
            &[jni::objects::JValue::Object(&action)],
        ) else {
            return false;
        };
        let _ = env.call_method(
            &intent,
            "setDataAndType",
            "(Landroid/net/Uri;Ljava/lang/String;)Landroid/content/Intent;",
            &[
                jni::objects::JValue::Object(&uri),
                jni::objects::JValue::Object(&mime_j),
            ],
        );
        // FLAG_GRANT_READ_URI_PERMISSION | FLAG_ACTIVITY_NEW_TASK
        let flags = 0x1 | 0x1000_0000;
        let _ = env.call_method(
            &intent,
            "addFlags",
            "(I)Landroid/content/Intent;",
            &[jni::objects::JValue::Int(flags)],
        );
        env.call_method(
            &ctx,
            "startActivity",
            "(Landroid/content/Intent;)V",
            &[jni::objects::JValue::Object(&intent)],
        )
        .is_ok()
    }

    /// 用系统 Toast 把一句话显示到屏幕上——启动失败时这是唯一能看见的出口。
    pub fn toast(msg: &str) {
        let jvm_ptr = JAVA_VM.load(Ordering::SeqCst);
        let ctx_ptr = APP_CTX.load(Ordering::SeqCst);
        if jvm_ptr.is_null() || ctx_ptr.is_null() {
            return;
        }
        let Ok(vm) = (unsafe { jni::JavaVM::from_raw(jvm_ptr.cast()) }) else {
            return;
        };
        let Ok(mut env) = vm.attach_current_thread() else {
            return;
        };
        let ctx = unsafe { jni::objects::JObject::from_raw(ctx_ptr.cast()) };
        let Ok(text) = env.new_string(msg) else {
            return;
        };
        let Ok(cls) = env.find_class("android/widget/Toast") else {
            return;
        };
        let args = [
            jni::objects::JValue::Object(&ctx),
            jni::objects::JValue::Object(&text),
            jni::objects::JValue::Int(1),
        ];
        let Some(toast) = env
            .call_static_method(
                cls,
                "makeText",
                "(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;",
                &args,
            )
            .ok()
            .and_then(|v| v.l().ok())
        else {
            return;
        };
        let _ = env.call_method(&toast, "show", "()V", &[]);
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
            // app_data_dir 走的是 JNI 里的 path 插件，失败时用 Application
            // 的 getFilesDir 兜底，别因为拿不到目录就把进程崩了。
            match app.path().app_data_dir() {
                Ok(dir) => dir,
                Err(err) => {
                    diag::trace(&format!("app_data_dir failed: {err}"));
                    #[cfg(target_os = "android")]
                    match android_ctx::files_dir() {
                        Some(dir) => dir,
                        None => return Err(Box::new(err)),
                    }
                    #[cfg(not(target_os = "android"))]
                    {
                        return Err(Box::new(err));
                    }
                }
            }
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
    // 提前初始化 ndk_context，避免 iroh 在后台线程 panic。
    #[cfg(target_os = "android")]
    {
        android_ctx::init();
        diag::trace("ndk_context init");
    }
    // 启动失败时不要静默消失：留下日志，并在手机上弹一句原因。
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(build_and_run));
    if let Err(payload) = outcome {
        let msg = panic_message(payload.as_ref());
        diag::trace(&format!("run() aborted: {msg}"));
        #[cfg(target_os = "android")]
        android_ctx::toast(&format!("PrivChat 启动失败：{msg}"));
    }
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|text| (*text).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic".to_string())
}

fn build_and_run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_notification::init())
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
            test_onion_relays,
            onion_relay_latency,
            ping_mailbox,
            add_mailbox_peer,
            set_mailbox_priority,
            remove_mailbox_peer,
            ping_mailboxes,
            get_mailbox_weight,
            set_mailbox_weight,
            mailbox_latency,
            get_auto_lock_minutes,
            set_auto_lock_minutes,
            create_connection,
            accept_connection,
            delete_connection,
            rotate_connection,
            export_attachment,
            search_messages,
            send_file,
            send_on_connection,
            list_connections,
            connection_history,
            rename_connection,
            exit_app,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|_app_handle, _event| {
            // 默认行为：所有窗口关闭后应用退出。不要在这里调用 app_handle.exit(0)——
            // 主线程调用 exit 会重入 ExitRequested/Exit 事件，导致进程无法干净终止。
        });
}
