#!/usr/bin/env bash
# ============================================================
# PrivChat — Android arm64 (aarch64) APK 编译脚本
#
# 用法：
#   bash scripts/build-android-arm64.sh                  # 用固定 debug key 自动签名
#   bash scripts/build-android-arm64.sh --no-sign        # 只出未签名 APK
#   bash scripts/build-android-arm64.sh --sign <keystore> <alias> <pass>
#
# 默认签名密钥由 scripts/android-keystore.sh 管理（首次自动生成到
# ~/.privchat/android/debug.keystore），保证每次编译出来的 APK 可以
# 直接覆盖安装；换密钥会让旧 APK 无法覆盖。
#
# 默认要求编译工具链完整：
#   - Rust stable + aarch64-linux-android 目标
#   - Node.js + npm
#   - Android SDK（ANDROID_HOME / ANDROID_SDK_ROOT 或常用安装路径）
#   - Android NDK（ANDROID_NDK_HOME / NDK_HOME 或 SDK 内 ndk/ 目录）
#   - JDK 17+，apksigner（SDK build-tools）
#   - Tauri CLI（随 privchat-client 的 devDependencies 安装）
#
# 产物复制到工作区 target/ 目录：
#   target/android-arm64/privchat-android-arm64.apk
#   target/android-arm64/privchat-android-arm64-unsigned.apk （未签名副本）
# ============================================================
set -euo pipefail

# —— 定位仓库根目录（脚本位于 $REPO_ROOT/scripts/）——
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CLIENT_DIR="$REPO_ROOT/privchat-client"
ARCH_DIR="$REPO_ROOT/target/android-arm64"

# —— 参数：--sign <keystore> <alias> <pass> / --no-sign ——
SIGN_KS="" SIGN_ALIAS="" SIGN_PASS="" NO_SIGN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --sign)
      [ $# -ge 4 ] || { echo "usage: --sign <keystore> <alias> <pass>" >&2; exit 1; }
      SIGN_KS="$2"; SIGN_ALIAS="$3"; SIGN_PASS="$4"; shift 4 ;;
    --no-sign)
      NO_SIGN=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

echo "[build] PrivChat Android arm64"
echo "[build] repo: $REPO_ROOT"
mkdir -p "$ARCH_DIR"

# —— 自动探测 Android SDK / NDK ——
find_sdk() {
  [ -n "${ANDROID_HOME:-}" ] && [ -d "$ANDROID_HOME" ] && { echo "$ANDROID_HOME"; return; }
  [ -n "${ANDROID_SDK_ROOT:-}" ] && [ -d "$ANDROID_SDK_ROOT" ] && { echo "$ANDROID_SDK_ROOT"; return; }
  for p in "$HOME/Android/Sdk" "/opt/android-sdk" "/usr/lib/android-sdk" "/mnt/c/Android/Sdk"; do
    [ -d "$p" ] && { echo "$p"; return; }
  done
  echo ""
}

find_ndk() {
  [ -n "${ANDROID_NDK_HOME:-}" ] && [ -d "$ANDROID_NDK_HOME" ] && { echo "$ANDROID_NDK_HOME"; return; }
  [ -n "${NDK_HOME:-}" ] && [ -d "$NDK_HOME" ] && { echo "$NDK_HOME"; return; }
  local sdk; sdk="$(find_sdk)"
  if [ -n "$sdk" ]; then
    for d in "$sdk"/ndk/*/; do
      [ -d "$d" ] && { echo "${d%/}"; return; }
    done
  fi
  echo ""
}

SDK="$(find_sdk)"
NDK="$(find_ndk)"
if [ -z "$SDK" ]; then
  echo "[build] ERROR: Android SDK not found (set ANDROID_HOME or ANDROID_SDK_ROOT)" >&2
  exit 1
fi
if [ -z "$NDK" ]; then
  echo "[build] ERROR: Android NDK not found (set ANDROID_NDK_HOME or NDK_HOME)" >&2
  exit 1
fi
export ANDROID_HOME="$SDK"
export ANDROID_SDK_ROOT="$SDK"
export ANDROID_NDK_HOME="$NDK"
export NDK_HOME="$NDK"
echo "[build] SDK: $SDK"
echo "[build] NDK: $NDK"

# —— 交叉编译工具链（openssl-sys 等 C 依赖需要显式给编译器）——
# 不设这些时 vendored OpenSSL 会去调 aarch64-linux-android-ranlib，
# 那是 NDK 里并不存在的名字，构建直接 127。
TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64"
[ -d "$TOOLCHAIN" ] || TOOLCHAIN="$(find "$NDK/toolchains/llvm/prebuilt" -mindepth 1 -maxdepth 1 -type d | head -1)"
if [ ! -d "$TOOLCHAIN" ]; then
  echo "[build] ERROR: NDK llvm toolchain not found under $NDK" >&2
  exit 1
fi
ANDROID_API=24   # 与 app/build.gradle.kts 的 minSdk 对齐
TC_CLANG="$TOOLCHAIN/bin/aarch64-linux-android${ANDROID_API}-clang"
[ -x "$TC_CLANG" ] || TC_CLANG="$TOOLCHAIN/bin/aarch64-linux-android-clang"
TC_AR="$TOOLCHAIN/bin/llvm-ar"
TC_RANLIB="$TOOLCHAIN/bin/llvm-ranlib"
for f in "$TC_CLANG" "$TC_AR" "$TC_RANLIB"; do
  [ -x "$f" ] || { echo "[build] ERROR: missing NDK tool: $f" >&2; exit 1; }
done
# cc crate 认下划线写法，可以直接 export；
# 带横线的写法（openssl-sys 的旧式查找）不是合法 shell 标识符，
# 只能在真正编译时用 env 前缀注入。
export CC_aarch64_linux_android="$TC_CLANG"
export AR_aarch64_linux_android="$TC_AR"
export RANLIB_aarch64_linux_android="$TC_RANLIB"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$TC_CLANG"
CROSS_ENV=(
  "CC_aarch64-linux-android=$TC_CLANG"
  "AR_aarch64-linux-android=$TC_AR"
  "RANLIB_aarch64-linux-android=$TC_RANLIB"
  "CC_aarch64_linux_android=$TC_CLANG"
  "AR_aarch64_linux_android=$TC_AR"
  "RANLIB_aarch64_linux_android=$TC_RANLIB"
)
echo "[build] CC: $TC_CLANG"

# —— 前端依赖 ——
if [ ! -d "$CLIENT_DIR/node_modules" ]; then
  echo "[build] installing frontend deps"
  (cd "$CLIENT_DIR" && npm install)
fi

# —— Rust aarch64-android 目标 ——
if ! rustup target list --installed | grep -q '^aarch64-linux-android$'; then
  echo "[build] adding rustup target aarch64-linux-android"
  rustup target add aarch64-linux-android
fi

# —— Tauri Android 构建（arm64 单架构 APK）——
echo "[build] building tauri android apk (this may take a while)"
(cd "$CLIENT_DIR" && env "${CROSS_ENV[@]}" npm run tauri android build -- --target aarch64 --apk --ci)

# —— 定位产物并复制到 target/android-arm64/ ——
UNSIGNED="$(find "$CLIENT_DIR/src-tauri/gen/android/app/build/outputs/apk" -name '*-unsigned.apk' -path '*aarch64*' 2>/dev/null | head -1)"
if [ -z "$UNSIGNED" ]; then
  UNSIGNED="$(find "$CLIENT_DIR/src-tauri/gen/android/app/build/outputs/apk" -name '*-unsigned.apk' 2>/dev/null | head -1)"
fi
if [ -z "$UNSIGNED" ]; then
  echo "[build] ERROR: no unsigned apk found under build/outputs/apk" >&2
  exit 1
fi
echo "[build] unsigned apk: $UNSIGNED"

cp -f "$UNSIGNED" "$ARCH_DIR/privchat-android-arm64-unsigned.apk"
echo "[build] -> $ARCH_DIR/privchat-android-arm64-unsigned.apk"

# —— 签名（默认用固定 debug key；--no-sign 跳过）——
if [ "$NO_SIGN" -eq 0 ]; then
  if [ -z "$SIGN_KS" ]; then
    eval "$(bash "$SCRIPT_DIR/android-keystore.sh" --ensure --eval)"
    SIGN_KS="$KEYSTORE"; SIGN_ALIAS="$ALIAS"; SIGN_PASS="$PASS"
    echo "[build] default debug keystore: $SIGN_KS"
  fi
  APKSIGNER=""
  for bt in "$SDK"/build-tools/*/apksigner; do
    [ -x "$bt" ] && { APKSIGNER="$bt"; break; }
  done
  [ -z "$APKSIGNER" ] && APKSIGNER="$(command -v apksigner || true)"
  if [ -z "$APKSIGNER" ]; then
    echo "[build] ERROR: apksigner not found" >&2
    exit 1
  fi
  # 签名前必须 zipalign：extractNativeLibs=false 的包会把 .so 直接从 apk 映射，
  # 16KB page 设备要求 16KB 对齐（老设备 4KB 也满足 16KB 边界）。
  ZIPALIGN="$(dirname "$APKSIGNER")/zipalign"
  SIGN_SRC="$UNSIGNED"
  if [ -x "$ZIPALIGN" ]; then
    ALIGNED="$ARCH_DIR/.privchat-android-arm64-aligned.apk"
    if ! "$ZIPALIGN" -p -f 16 "$UNSIGNED" "$ALIGNED" 2>/dev/null; then
      echo "[build] zipalign 16K failed, falling back to 4K" >&2
      "$ZIPALIGN" -p -f 4 "$UNSIGNED" "$ALIGNED"
    fi
    SIGN_SRC="$ALIGNED"
  else
    echo "[build] WARN: zipalign not found, apk left unaligned" >&2
  fi
  echo "[build] signing with $APKSIGNER"
  "$APKSIGNER" sign --ks "$SIGN_KS" --ks-key-alias "$SIGN_ALIAS" \
    --ks-pass "pass:$SIGN_PASS" --key-pass "pass:$SIGN_PASS" \
    --out "$ARCH_DIR/privchat-android-arm64.apk" "$SIGN_SRC"
  if [ -n "${ALIGNED:-}" ]; then
    rm -f "$ALIGNED"
    "$ZIPALIGN" -c -p 16 "$ARCH_DIR/privchat-android-arm64.apk" >/dev/null 2>&1 \
      && echo "[build] zipalign: 16K ok" || echo "[build] WARN: apk not 16K aligned" >&2
  fi
  "$APKSIGNER" verify --print-certs "$ARCH_DIR/privchat-android-arm64.apk" | head -5 || true
  echo "[build] -> $ARCH_DIR/privchat-android-arm64.apk"
else
  echo "[build] (--no-sign: skipped signing)"
  cp -f "$UNSIGNED" "$ARCH_DIR/privchat-android-arm64.apk"
fi

echo "[build] done."
ls -la "$ARCH_DIR"