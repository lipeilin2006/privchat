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
| **端到端加密** | 双棘轮 + AEAD（ChaCha20-Poly1305），发送失败不推进密钥链 |
| **每联系人独立身份** | 每个联系人一个 SecretKey / Endpoint，跨联系人不可关联 |
| **邮箱投递** | 消息先加密再交给 mailbox 节点，节点只见密文，取回即删 |
| **多副本冗余** | 每条消息可配置「最多成功推送节点数」（默认 3） |
| **洋葱路由** | 多层加密逐跳转发，中继只知邻居，不知全貌 |
| **网格同步** | mailbox 之间广播同步、失败重试、新节点补推 |
| **邻居自动扩充** | PEX：节点周期性交换邻居列表，自动组网 |
| **本地保险箱** | SQLCipher 全库加密，密码解锁，支持自动锁定 |
| **跨平台** | Android / Windows / macOS / Linux（Tauri 2） |
| **命令行客户端** | 文本、图片、洋葱路径，可在无 GUI 环境端到端验证 |

---

## 🏗 架构

```
┌─────────────────────────────────────────────────────────────┐
│                        privchat-client                       │
│  Tauri 2 + React 18 + @telegram-apps/telegram-ui              │
│                                                              │
│   L2   app      身份 / 联系人 / 历史 / 发送队列               │
│   L2.5 crypto   双棘轮 E2EE（ChaCha20-Poly1305）             │
│   L1.5 mailbox  mailbox 客户端：put_multi / fetch            │
│   L0.5 store    SQLCipher 本地持久化                          │
│   L1   transport iroh QUIC（生产模式只拨号，不再 P2P 收发）   │
└───────────────┬─────────────────────────────────────────────┘
                │  put / fetch（密文）
                ▼
┌─────────────────────────────────────────────────────────────┐
│                      privchat-mailbox                        │
│  按接收方 peer_id 分类的密文队列（SQLite，取回即删）          │
│  ├─ role = mailbox / relay / both                            │
│  ├─ PEX：邻居自动扩充（默认 60s）                              │
│  └─ 同步：Sync 广播 + 3 次重试 + 新节点补推                    │
└───────────────┬─────────────────────────────────────────────┘
                │  ONION_ALPN（可选）
                ▼
┌─────────────────────────────────────────────────────────────┐
│                       privchat-onion                         │
│  wrap(relays, payload) 倒序套层 → peel() 逐跳剥离            │
│  每层：eph_pub(32) | nonce(12) | AEAD(next(32)|len(2)|inner) │
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
├── privchat-mailbox/           离线消息节点（角色 / PEX / 同步）
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

### 1. 启动一个 mailbox 节点

```bash
cd privchat-mailbox
PRIVCHAT_MAILBOX_DATA_DIR=/tmp/pmb cargo run --release
```

首次启动会生成 `secret.key` / `config.json` / `mailboxes.json`，并打印
`peer_id`——把它填进客户端设置即可。节点配置详见
[privchat-mailbox/CONFIG.md](privchat-mailbox/CONFIG.md)。

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
#   签名：bash scripts/build-android-arm64.sh --sign <keystore> <alias> <pass>
#   产物：target/android-arm64/privchat-android-arm64.apk
```

其他脚本：`build-windows-x86_64.sh`、`build-linux-x86_64.sh`、
`build-android-wsl.sh`、`build-windows.ps1`。

### 4. 命令行端到端验证（无需 GUI）

```bash
cd privchat-cli
cargo run -- init alice
cargo run -- init bob
cargo run -- derive bob alice      # 为联系人派生专属身份
cargo run -- contact bob <alice>   # 登记联系人
cargo run -- send alice bob "hi" --mailbox <node_id>
cargo run -- recv bob --mailbox <node_id>
cargo run -- demo <node_id>        # 一键自测
cargo run -- send-image alice bob ./a.png --mailbox <node_id>
```

完整用法与洋葱路径示例见 [privchat-cli/README.md](privchat-cli/README.md)。

---

## ⚙️ 配置

### 客户端（设置页）

| 项 | 说明 |
|---|---|
| Mailbox 节点 | 离线消息存储节点；未配置则无法发送 |
| 洋葱路由 | 开关 + 中继路径（顺序即转发顺序，最后一跳须为 mailbox） |
| 副本数 | 每条消息最多成功推送的节点数（0 = 全部，默认 3） |
| 自动锁定 | 永不 / 1 分钟 / 5 分钟 |
| 语言 | 中文 / English |

### mailbox 节点

```json
{ "ttl_secs": 604800, "role": "both" }
```

| 字段 | 说明 |
|---|---|
| `ttl_secs` | 密文保留秒数，0 = 永久 |
| `role` | `both` / `relay`（只转发）/ `mailbox`（只存储） |

角色分离的意义：**首跳中继与终点 mailbox 应由不同运营者部署**，否则同一
节点同时看到「发送方」和「收件人队列」，洋葱匿名性失效。

环境变量：`PRIVCHAT_MAILBOX_DATA_DIR`、`PRIVCHAT_MAILBOX_ROLE`、
`PRIVCHAT_MAILBOX_TTL_SECS`、`PRIVCHAT_MAILBOX_PEERS`、
`PRIVCHAT_MAILBOX_PEX_SECS`。

---

## 🔐 安全模型

- **无主身份**：每个联系人独立 SecretKey + Endpoint，跨联系人不关联。
- **前向保密**：双棘轮按条推进密钥；失败不提交，收方跳过窗口自愈乱序。
- **最小暴露**：mailbox 只存 `(to_peer_id, msg_id, ciphertext)`，不存发送方。
- **统一投递**：客户端不再直连对端，减少 IP 暴露面；所有消息经 mailbox。
- **可选洋葱**：多层加密逐跳转发；中继无法得知完整路径与内容。
- **本地加密**：SQLCipher 全库加密，密钥由密码派生，明文不落盘。

---

## 🧪 测试

```bash
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
- 未做固定长度分片/填充，包长会泄漏跳数与大致内容长度
- 未实现路径选择策略与守卫节点，恶意中继可做流量关联
- PEX 只扩充邻居表，不做历史消息的全量反熵同步
- GUI 尚未迁移：消息搜索、扫码添加、会话信息面板（CLI 已支持）

---

## 📚 文档

- [privchat-mailbox/CONFIG.md](privchat-mailbox/CONFIG.md) — 节点配置、角色、PEX
- [privchat-cli/README.md](privchat-cli/README.md) — CLI 用法、图片与洋葱路径
- [docs/SECURITY.md](docs/SECURITY.md) — 威胁模型、安全审查与抗追踪分析

---

## License

[MIT](LICENSE)
