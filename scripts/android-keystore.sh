#!/usr/bin/env bash
# ============================================================
# PrivChat — Android 本地签名密钥（固定 debug key）
#
# 目的：让每次编译出的 APK 都用同一把密钥签名，覆盖安装时
# 不用先卸载（不同密钥签的 APK 无法覆盖安装）。
#
# ⚠ 这不是生产密钥：口令是公开的，只适合自用 / 测试分发。
#    要上架或对外分发，请换成自己的密钥并用
#    `build-android-arm64.sh --sign <keystore> <alias> <pass>`。
#
# 用法：
#   bash scripts/android-keystore.sh --ensure [--eval]
#       密钥不存在就生成；--eval 输出可 eval 的 KEYSTORE/ALIAS/PASS 行
#   bash scripts/android-keystore.sh --show
#       只打印当前配置，不生成
#   bash scripts/android-keystore.sh --gen
#       强制重建（旧 APK 将无法覆盖安装）
#
# 环境变量：
#   PRIVCHAT_KEYSTORE  自定义密钥路径
#                      （默认 ~/.privchat/android/debug.keystore，不入库）
# ============================================================
set -euo pipefail

KEYSTORE="${PRIVCHAT_KEYSTORE:-$HOME/.privchat/android/debug.keystore}"
ALIAS="privchat-debug"
PASS="privchat-debug"
DNAME="CN=PrivChat Debug, OU=dev, O=PrivChat, L=local, C=CN"

usage() {
  sed -n '2,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 1
}

find_keytool() {
  local kt=""
  [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/keytool" ] && kt="$JAVA_HOME/bin/keytool"
  [ -z "$kt" ] && kt="$(command -v keytool || true)"
  if [ -z "$kt" ]; then
    echo "[keystore] ERROR: keytool not found (需要 JDK 17+)" >&2
    return 1
  fi
  echo "$kt"
}

# 密钥存在且能解开、且含目标别名
has_keystore() {
  [ -f "$KEYSTORE" ] || return 1
  "$(find_keytool)" -list -keystore "$KEYSTORE" -storepass "$PASS" -alias "$ALIAS" >/dev/null 2>&1
}

gen_keystore() {
  local kt; kt="$(find_keytool)"
  mkdir -p "$(dirname "$KEYSTORE")"
  echo "[keystore] generating $KEYSTORE (alias=$ALIAS)" >&2
  "$kt" -genkeypair \
    -keystore "$KEYSTORE" \
    -storetype PKCS12 \
    -storepass "$PASS" \
    -keypass "$PASS" \
    -alias "$ALIAS" \
    -keyalg RSA -keysize 2048 -validity 10000 \
    -dname "$DNAME" >/dev/null 2>&1
  chmod 600 "$KEYSTORE"
  echo "[keystore] done" >&2
}

emit() {
  if [ "${1:-}" = "--eval" ]; then
    printf "KEYSTORE=%q\nALIAS=%q\nPASS=%q\n" "$KEYSTORE" "$ALIAS" "$PASS"
  else
    echo "keystore: $KEYSTORE"
    echo "alias:    $ALIAS"
    echo "pass:     $PASS"
  fi
}

EVAL=""
MODE=""
for arg in "$@"; do
  case "$arg" in
    --eval) EVAL="--eval" ;;
    --ensure|--show|--gen) MODE="${arg#--}" ;;
    -h|--help) usage ;;
    *) echo "[keystore] unknown arg: $arg" >&2; usage ;;
  esac
done

case "$MODE" in
  ensure)
    has_keystore || gen_keystore
    emit "$EVAL"
    ;;
  show)
    [ -f "$KEYSTORE" ] || { echo "[keystore] 未找到: $KEYSTORE" >&2; exit 1; }
    has_keystore || { echo "[keystore] 密钥存在但无法用预期口令/别名打开: $KEYSTORE" >&2; exit 1; }
    emit "$EVAL"
    ;;
  gen)
    rm -f "$KEYSTORE"
    gen_keystore
    emit "$EVAL"
    ;;
  *)
    usage
    ;;
esac
