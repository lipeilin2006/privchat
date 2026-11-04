# PrivChat

> 端到端加密聊天：消息统一经 **mailbox 节点**投递，可选 **洋葱路由**多层转发；
> 双棘轮（Double Ratchet）提供前向保密，SQLCipher 加密全部本地数据。

PrivChat 是一个以 **iroh（QUIC）** 为传输层、以 **mailbox 网格**为投递层的
即时通信项目。客户端、mailbox 节点、洋葱路由、命令行测试工具都在同一个
Cargo workspace 里，二进制与协议共用一份代码。

---

## ✨ 特性

| 能力 | 说明 |
|---|---|
| **端到端加密** | 每连接独立 X25519 + 对称棘轮 + AEAD（ChaCha20-Poly1305），每 100 条换整条链 |
| **没有长期身份** | 连接密钥一次一换，跨连接不可关联；联系人只是本端备注 |
| **单向队列** | 每条队列绑定一台 mailbox，邀请即写权限，取回即删 |
| **队列轮换** | 每 500 条消息换一条新队列（可换节点），旧队列排空后删除 |
| **洋葱路由** | 多层加密逐跳转发，中继只知邻居，不知全貌 |
| **本地保险箱** | SQLCipher 全库加密，密码解锁，支持自动锁定 |
| **跨平台** | Android / Windows / macOS / Linux（Tauri 2） |

---

## 🏗 架构

```
┌─────────────────────────────────────────────────────────────┐
│                        privchat-client                       │
│  Tauri 2 + React 18 + @telegram-apps/telegram-ui              │
│                                                              │
│   L2   app      连接 / 备注 / 消息历史 / 轮询                 │
│   L2.5 crypto   每连接 DH + 对称棘轮 + 每 100 条换钥          │
│   L1.5 mailbox  队列客户端：create / send / get / delete      │
│   L0.5 store    SQLCipher 本地持久化                          │
│   L1   transport iroh QUIC（每条连接一条临时拨号身份）        │
└───────────────┬─────────────────────────────────────────────┘
                │  队列操作（密文 + Ed25519 签名）
                ▼
┌─────────────────────────────────────────────────────────────┐
│                      privchat-mailbox                        │
│  按 queue_id 分类的密文队列（SQLite，取回即删）               │
│  同时作为洋葱终点点（收最内层）；不做转发                     │
│  节点之间不需要同步（每条队列只属于一台节点）                 │
└───────────────┬─────────────────────────────────────────────┘
                │  ONION_ALPN（可选）
                ▼
┌─────────────────────────────────────────────────────────────┐
│                       privchat-onion                         │
│  wrap(relays, payload) 倒序套层 → peel() 逐跳剥离            │
└─────────────────────────────────────────────────────────────┘
```

---

## 📦 仓库结构

```
privchat/
├── privchat-client/            Tauri 2 客户端
│   ├── src/                    React 18 前端
│   │   ├── App.jsx             状态 / 路由 / 底部标签栏 / 返回键
│   │   ├── api.js              Tauri 命令封装
│   │   ├── i18n.js             中英文案
│   │   ├── utils/format.js     头像取色 / 首字母 / 时间格式化
│   │   ├── components/         ChatList / ChatWindow / ContactsPage / …
│   │   ├── pages/settings/     设置、mailbox、洋葱、改密（按页面拆分）
│   │   └── styles.css          Telegram 风格样式
│   ├── src-tauri/              Rust 后端（分层见上）
│   └── dev/                    无浏览器 UI 测试（puppeteer + mock）
│
├── privchat-common/            wire 协议 / PoW / ALPN
├── privchat-mailbox/           信箱节点（队列存储 + 洋葱终点）
├── privchat-relay/             洋葱中继节点（只转发，不落库）
├── privchat-onion/             洋葱路由封装与剥离
├── scripts/                    一键构建脚本
└── README.md
```

各 crate 规模：client ≈ 5.3k 行 Rust + 1.6k 行前端，mailbox ≈ 1.3k，
onion ≈ 240，common ≈ 260，cli ≈ 860。

---

## 🚀 快速开始

### 环境要求

- Rust stable（`rustup`）+ Cargo
- Node.js 18+ / npm
- 桌面：Tauri 2 的系统依赖（Linux 需 `libwebkit2gtk-4.1-dev` 等）
- Android：JDK 17+、Android SDK、NDK、`aarch64-linux-android` target

### 1. 启动一个信箱节点

```bash
cd privchat-mailbox
PRIVCHAT_MAILBOX_DATA_DIR=/tmp/pmb cargo run --release
```

首次启动会生成 `secret.key` / `config.json`，并打印 `peer_id`——
填进客户端「信箱」。配置见 [privchat-mailbox/CONFIG.md](privchat-mailbox/CONFIG.md)。

### 1b. 启动一个洋葱中继节点（可选）

```bash
cd privchat-relay
PRIVCHAT_RELAY_DATA_DIR=/tmp/prelay cargo run --release
```

打印的 `peer_id` 填进客户端「洋葱路由」的中继列表。配置见
[privchat-relay/CONFIG.md](privchat-relay/CONFIG.md)。
信箱和中继是两个独立程序，可以部署在不同机器 / 不同运营者。

### 2. 开发运行客户端

```bash
cd privchat-client
npm install
npm run tauri dev          # 桌面开发（Vite 热更新）
```

### 3. 构建发布

```bash
# 桌面（当前平台）
cd privchat-client && npm run tauri build

# Android arm64（APK）
bash scripts/build-android-arm64.sh
#   默认用固定 debug key 自动签名：
#   密钥由 scripts/android-keystore.sh 管理（首次生成到
#   ~/.privchat/android/debug.keystore），同一把钥匙 → 可直接覆盖安装
#   换自己的密钥：bash scripts/build-android-arm64.sh --sign <keystore> <alias> <pass>
#   只出未签名包：bash scripts/build-android-arm64.sh --no-sign
#   单独签一个已有 APK：bash scripts/sign-apk.sh <unsigned.apk> [out.apk]
#   产物：target/android-arm64/privchat-android-arm64.apk
```

> debug key 的口令是公开的，只适合自用 / 测试分发；对外发布请换自己的密钥。

其他脚本：`build-windows-x86_64.sh`、`build-linux-x86_64.sh`、
`build-android-wsl.sh`、`build-windows.ps1`。



## ⚙️ 配置

### 客户端（设置页）

| 项 | 说明 |
|---|---|
| Mailbox 节点 | 离线消息存储节点；未配置则无法发送 |
| 洋葱路由 | 开关 + 中继路径（顺序即转发顺序，最后一跳须为 mailbox）；开启后队列请求经中继转发 |
| 自动锁定 | 永不 / 1 分钟 / 5 分钟 |
| 语言 | 中文 / English |

### 信箱节点 / 中继节点

两个独立程序、各自一个 config.json：

```json
// privchat-mailbox：队列存储 + 洋葱终点
{ "ttl_secs": 604800, "bind": "0.0.0.0:8443" }

// privchat-relay：只转发，不落库
{ "bind": "0.0.0.0:8444", "onion_peers": [] }
```

分离的意义：**首跳中继与终点信箱应由不同运营者部署**，否则同一节点
同时看到「发送方」和「收件人队列」，洋葱匿名性失效。

细节见 [privchat-mailbox/CONFIG.md](privchat-mailbox/CONFIG.md) 和
[privchat-relay/CONFIG.md](privchat-relay/CONFIG.md)。

---

## 🔐 安全模型

- **没有长期身份**：每条连接一套临时密钥，跨连接不可关联。
- **前向保密**：链密钥按条推进，每 100 条换整条链；派生后丢弃 root。
- **最小暴露**：mailbox 只存 `(queue_id, ciphertext)`，不存发送方。
- **统一投递**：客户端只连 mailbox，不直连对端。
- **可选洋葱**：多层加密逐跳转发；中继无法得知完整路径与内容。
- **本地加密**：SQLCipher 全库加密，密钥由密码派生，明文不落盘。

---

## 🧪 测试

```bash
# 一键：fmt 检查 + clippy(warning=失败) + 全 workspace 测试
bash scripts/check.sh

# Rust：客户端 lib + mailbox + common + onion
cargo test -p privchat-client --lib -- --test-threads=1
cargo test -p privchat-mailbox
cargo test -p privchat-onion

# 前端：mock 构建 + puppeteer 点击冒烟
cd privchat-client
npm run mock
npm run uitest
```

---

## ⚠️ 已知限制

- 洋葱投递目前是**单向**的：没有匿名回程，终点只接受 `put`
- 洋葱投递未做固定长度分片，首跳仍能看到上传者的 TLS 身份
- 未实现路径选择策略与守卫节点，恶意中继可做流量关联
- 单队列绑一台 mailbox：节点故障期间不可达（靠 TTL 与轮换兜底）
- 元数据：时间、大小、同一连接的两条队列仍可被节点关联
- GUI 尚未实现：消息搜索、会话信息面板

---

## 📚 文档

- [privchat-mailbox/CONFIG.md](privchat-mailbox/CONFIG.md) — 信箱配置、TTL、限额
- [privchat-relay/CONFIG.md](privchat-relay/CONFIG.md) — 中继配置、转发白名单
- [docs/SECURITY.md](docs/SECURITY.md) — 威胁模型、安全审查与抗追踪分析

---

## License

[MIT](LICENSE)
