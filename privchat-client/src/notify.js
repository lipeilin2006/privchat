//! 本地通知封装：桌面/浏览器里没有通知能力，失败就静默。
import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from "@tauri-apps/plugin-notification";

let asked = false;

/// 解锁后调一次，把权限要下来（拒绝也没关系，后面不再打扰）。
export async function ensureNotificationPermission() {
  try {
    if (await isPermissionGranted()) return true;
    if (asked) return false;
    asked = true;
    return (await requestPermission()) === "granted";
  } catch {
    return false;
  }
}

/// 有新消息时弹一条；只在 App 不在前台时调用。
export async function notifyMessage(title, body) {
  try {
    if (!(await isPermissionGranted())) return;
    sendNotification({ title, body });
  } catch {
    // 不支持通知的环境就算了
  }
}
