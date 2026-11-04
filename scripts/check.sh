#!/usr/bin/env bash
# ============================================================
# PrivChat — 一键自检
#
#   bash scripts/check.sh
#
# 依次跑：rustfmt 检查 → clippy（warning 视为失败）→ 全 workspace 测试。
# 提交前跑一遍，省得 CI/别人捡到低级问题。
# ============================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# cargo 装在 ~/.cargo/bin 但当前 shell 没带上 PATH 时也能跑。
if ! command -v cargo >/dev/null 2>&1; then
  export PATH="$HOME/.cargo/bin:$PATH"
fi
command -v cargo >/dev/null 2>&1 || {
  echo "[check] ERROR: cargo not found" >&2
  exit 1
}

echo "[check] rustfmt"
cargo fmt --all -- --check

echo "[check] clippy"
cargo clippy --workspace --all-targets -- -D warnings

echo "[check] tests"
cargo test --workspace

echo "[check] ok"
