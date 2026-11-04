#!/usr/bin/env bash
# ============================================================
# PrivChat — 部署 mailbox 节点到一台 Linux（systemd）机器
#
#   bash scripts/deploy-mailbox.sh <ssh 目标> [udp 端口]
#   bash scripts/deploy-mailbox.sh root@1.2.3.4 8443
#
# 做的事：
#   1. 本机编译 privchat-mailbox 的 release 二进制
#   2. 传到目标机 /usr/local/bin/privchat-mailbox
#   3. 建 privchat 用户 + /etc/privchat/mailbox.env + systemd 单元
#   4. 启动并在最后打印 peer_id（填到客户端「Mailbox」里）
#
# 前提：目标机是 Linux + systemd，SSH 已能免密登录（密钥）。
# 重跑是幂等的：二进制会替换，服务会重启，数据目录不动。
# ============================================================
set -euo pipefail

TARGET="${1:-}"
PORT="${2:-8443}"
if [ -z "$TARGET" ]; then
  echo "usage: bash scripts/deploy-mailbox.sh <user@host> [udp_port]" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
  export PATH="$HOME/.cargo/bin:$PATH"
fi

echo "[deploy] 编译 mailbox（release）"
cargo build -p privchat-mailbox --release

BIN="$REPO_ROOT/target/release/privchat-mailbox"
[ -x "$BIN" ] || { echo "[deploy] 找不到 $BIN" >&2; exit 1; }

echo "[deploy] 传输文件到 $TARGET"
scp -q "$BIN" "$TARGET:/tmp/privchat-mailbox"
scp -q "$REPO_ROOT/packaging/privchat-mailbox.service" "$TARGET:/tmp/privchat-mailbox.service"

# 目标机上安装（用 heredoc 一次跑完，避免多条 SSH 会话）
ssh "$TARGET" bash -s -- "$PORT" <<'REMOTE'
set -euo pipefail
PORT="$1"

install -m 0755 /tmp/privchat-mailbox /usr/local/bin/privchat-mailbox
rm -f /tmp/privchat-mailbox

id -u privchat >/dev/null 2>&1 || useradd --system --home /var/lib/privchat-mailbox --shell /usr/sbin/nologin privchat
install -d -m 0700 -o privchat -g privchat /var/lib/privchat-mailbox
install -d -m 0755 /etc/privchat

if [ ! -f /etc/privchat/mailbox.env ]; then
  cat > /etc/privchat/mailbox.env <<EOF
PRIVCHAT_MAILBOX_DATA_DIR=/var/lib/privchat-mailbox
EOF
  chmod 0644 /etc/privchat/mailbox.env
  echo "[remote] 写入 /etc/privchat/mailbox.env"
else
  echo "[remote] 保留已有 /etc/privchat/mailbox.env"
fi

# 节点配置统一在 config.json；已存在就不动，避免覆盖手工调过的值
if [ ! -f /var/lib/privchat-mailbox/config.json ]; then
  cat > /var/lib/privchat-mailbox/config.json <<EOF
{
  "ttl_secs": 604800,
  "role": "both",
  "bind": "0.0.0.0:${PORT}",
  "onion_peers": [],
  "max_queue_msgs": 1000,
  "max_queue_bytes": 67108864,
  "max_queues": 50000
}
EOF
  chown privchat:privchat /var/lib/privchat-mailbox/config.json
  chmod 0600 /var/lib/privchat-mailbox/config.json
  echo "[remote] 写入 /var/lib/privchat-mailbox/config.json"
else
  echo "[remote] 保留已有 config.json"
fi

install -m 0644 /tmp/privchat-mailbox.service /etc/systemd/system/privchat-mailbox.service
rm -f /tmp/privchat-mailbox.service

systemctl daemon-reload
systemctl enable --now privchat-mailbox >/dev/null
systemctl restart privchat-mailbox
sleep 2
systemctl --no-pager --lines=15 status privchat-mailbox || true
REMOTE

echo
echo "[deploy] 完成。上面的 peer_id 就是客户端里要填的节点 id。"
echo "[deploy] 记得在云安全组/防火墙放行 UDP $PORT（否则只能走 relay 中继）。"
