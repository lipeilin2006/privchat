#!/usr/bin/env bash
# ============================================================
# PrivChat — 给已有的未签名 APK 签名
#
# 用法：
#   bash scripts/sign-apk.sh <未签名.apk> [输出.apk]
#   bash scripts/sign-apk.sh <未签名.apk> [输出.apk] --sign <keystore> <alias> <pass>
#
# 不传 --sign 时使用 scripts/android-keystore.sh 管理的固定 debug key
# （首次自动生成），保证和 build-android-arm64.sh 签出来的是同一把。
#
# apksigner 从 ANDROID_HOME/build-tools/*/ 或 PATH 里找。
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

INPUT=""
OUTPUT=""
SIGN_KS="" SIGN_ALIAS="" SIGN_PASS=""

while [ $# -gt 0 ]; do
  case "$1" in
    --sign)
      [ $# -ge 4 ] || { echo "usage: --sign <keystore> <alias> <pass>" >&2; exit 1; }
      SIGN_KS="$2"; SIGN_ALIAS="$3"; SIGN_PASS="$4"; shift 4 ;;
    -h|--help)
      sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)
      if [ -z "$INPUT" ]; then INPUT="$1"
      elif [ -z "$OUTPUT" ]; then OUTPUT="$1"
      else echo "unknown arg: $1" >&2; exit 1
      fi
      shift ;;
  esac
done

[ -n "$INPUT" ] || { echo "[sign] usage: sign-apk.sh <unsigned.apk> [out.apk]" >&2; exit 1; }
[ -f "$INPUT" ] || { echo "[sign] 找不到: $INPUT" >&2; exit 1; }
[ -n "$OUTPUT" ] || OUTPUT="${INPUT%-unsigned.apk}.apk"
[ "$OUTPUT" = "$INPUT" ] && { echo "[sign] 输出不能覆盖输入" >&2; exit 1; }

if [ -z "$SIGN_KS" ]; then
  eval "$(bash "$SCRIPT_DIR/android-keystore.sh" --ensure --eval)"
  SIGN_KS="$KEYSTORE"; SIGN_ALIAS="$ALIAS"; SIGN_PASS="$PASS"
fi

find_apksigner() {
  local sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
  local out=""
  if [ -n "$sdk" ]; then
    for bt in "$sdk"/build-tools/*/apksigner; do
      [ -x "$bt" ] && { out="$bt"; }
    done
  fi
  [ -z "$out" ] && out="$(command -v apksigner || true)"
  echo "$out"
}

APKSIGNER="$(find_apksigner)"
[ -n "$APKSIGNER" ] || { echo "[sign] ERROR: apksigner not found (设 ANDROID_HOME 或装 build-tools)" >&2; exit 1; }

echo "[sign] $INPUT"
echo "[sign] -> $OUTPUT"
"$APKSIGNER" sign --ks "$SIGN_KS" --ks-key-alias "$SIGN_ALIAS" \
  --ks-pass "pass:$SIGN_PASS" --key-pass "pass:$SIGN_PASS" \
  --out "$OUTPUT" "$INPUT"
"$APKSIGNER" verify --print-certs "$OUTPUT" | head -5
echo "[sign] done: $(ls -la "$OUTPUT" | awk '{print $5" bytes"}')"
