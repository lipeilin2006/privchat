#!/usr/bin/env bash
# ============================================================
# PrivChat — 部署洋葱中继节点（privchat-relay）
#
#   bash scripts/deploy-relay.sh <ssh 目标> [udp 端口]
#   bash scripts/deploy-relay.sh root@1.2.3.4 8444
#
# 做的事：
#   1. 本机编译 privchat-relay 的 release 二进制
#   2. 传到目标机 /usr/local/bin/privchat-relay
#   3. 建 privchat-relay 用户 + /etc/privchat/relay.env + systemd 单元
#   4. 启动并打印 peer_id（填到客户端「洋葱路由」的中继列表里）
#
# 前提：Linux + systemd，SSH 免密（密钥）。重跑幂等，数据目录不动。
# ============================================================
set -euo pipefail

TARGET="${1:-}"
PORT="${2:-8444}"
if [ -z "$TARGET" ]; then
  echo "usage: bash scripts/deploy-relay.sh <user@host> [udp_port]" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
  export PATH="$HOME/.cargo/bin:$PATH"
fi

echo "[deploy] 编译 privchat-relay（release）"
cargo build -p privchat-relay --release

BIN="$REPO_ROOT/target/release/privchat-relay"
[ -x "$BIN" ] || { echo "[deploy] 找不到 $BIN" >&2; exit 1; }

echo "[deploy] 传输文件到 $TARGET"
scp -q "$BIN" "$TARGET:/tmp/privchat-relay"
scp -q "$REPO_ROOT/packaging/privchat-relay.service" "$TARGET:/tmp/privchat-relay.service"

ssh "$TARGET" bash -s -- "$PORT" <<'REMOTE'
set -euo pipefail
PORT="$1"

install -m 0755 /tmp/privchat-relay /usr/local/bin/privchat-relay
rm -f /tmp/privchat-relay

id -u privchat-relay >/dev/null 2>&1 || useradd --system --home /var/lib/privchat-relay --shell /usr/sbin/nologin privchat-relay
install -d -m 0700 -o privchat-relay -g privchat-relay /var/lib/privchat-relay
install -d -m 0755 /etc/privchat

if [ ! -f /etc/privchat/relay.env ]; then
  printf 'PRIVCHAT_RELAY_DATA_DIR=/var/lib/privchat-relay\n' > /etc/privchat/relay.env
  chmod 0644 /etc/privchat/relay.env
  echo "[remote] 写入 /etc/privchat/relay.env"
else
  echo "[remote] 保留已有 /etc/privchat/relay.env"
fi

# 配置统一在 config.json；已存在不动
if [ ! -f /var/lib/privchat-relay/config.json ]; then
  cat > /var/lib/privchat-relay/config.json <<EOF
{
  "bind": "0.0.0.0:${PORT}",
  "onion_peers": []
}
EOF
  chown privchat-relay:privchat-relay /var/lib/privchat-relay/config.json
  chmod 0600 /var/lib/privchat-relay/config.json
  echo "[remote] 写入 /var/lib/privchat-relay/config.json"
else
  echo "[remote] 保留已有 config.json"
fi

install -m 0644 /tmp/privchat-relay.service /etc/systemd/system/privchat-relay.service
rm -f /tmp/privchat-relay.service

systemctl daemon-reload
systemctl enable --now privchat-relay >/dev/null
systemctl restart privchat-relay
sleep 2
systemctl --no-pager --lines=12 status privchat-relay || true
REMOTE

echo
echo "[deploy] 完成。上面的 peer_id 填到客户端「洋葱路由」里。"
echo "[deploy] 记得在云安全组/防火墙放行 UDP $PORT（否则只能走 relay 中继发现）。"
