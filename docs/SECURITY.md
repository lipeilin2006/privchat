# 安全与抗追踪说明

本文记录 PrivChat 的威胁模型、已知问题、已采取的缓解措施，以及部署建议。
审查基于当前 `main` 分支代码，结论按**严重程度**排序。

---

## 1. 威胁模型

| 角色 | 能力 | 我们防什么 |
|---|---|---|
| 被动网络观察者 | 看得到连接元数据、包长、时序 | 内容保密、尽量少泄漏长度/时序 |
| 恶意 mailbox 节点 | 收 `put`/`fetch`，存密文，可看 TLS 身份与到达时间 | 内容保密、不存发送方、取回即删 |
| 恶意洋葱中继 | 剥一层、转发下一跳 | 内容保密、不暴露完整路径 |
| 恶意对端 | 发消息、发图片、发畸形包 | 解析安全、不写越界路径、不 OOM |
| 本地设备丢失 | 拿到磁盘文件 | 全库加密 + 密码派生 |

**不防**：拥有 root 权限的节点运营者做全局流量关联、拿到收发双方设备的攻击者。

---

## 2. 已发现的问题

| ID | 严重度 | 问题 | 状态 |
|---|---|---|---|
| S1 | **高** | CLI 接收图片时直接用清单里的文件名落盘，可被 `../` 路径穿越写任意文件 | ✅ 已修复（只取 `file_name()`，过滤 `.`/`..`） |
| S2 | 中 | 洋葱中继按 16 MB 上限读取单包（实际包 ≤ 64 KB），恶意客户端可做内存放大 | ✅ 已修复（`ONION_PACKET_MAX = 128 KB`） |
| S3 | 中 | `put` 无发送方认证，PoW 难度仅 1 字节（平均 256 次哈希）→ 队列灌水成本极低 | ⚠️ 已知，建议提高难度（见下） |
| S4 | 中 | 洋葱中继允许转发到**任意** peer id（开放中继），可被用来探测内网/第三方节点 | ✅ 可缓解：`PRIVCHAT_MAILBOX_ONION_PEERS` 白名单 |
| S5 | 中 | 无定长分片/填充，包长泄漏"几跳 + 大致内容长度" | ✅ 部分缓解：明文桶填充（见 3.6） |
| S6 | 低 | `msg_id = gen:n`，节点可看出会话消息序号与总数 | ⚠️ 已知（排序需要） |
| S7 | 低 | mailbox 存储到达时间（TTL 需要），可做发送频率画像 | ⚠️ 可改为小时粒度 |
| S8 | 低 | 节点日志会打印 peer id 与包长 | ✅ 已缓解：日志只打印 peer_id 前 12 位 |
| S9 | **高** | WebView 未设置 CSP（`app.security.csp = null`），一旦有注入即可调用 Tauri 命令 | ✅ 已修复（见下） |
| S10 | 中 | 安卓默认允许 `adb backup` 导出应用数据 | ✅ 已修复（`allowBackup=false`） |

---

## 3. 抗追踪分析

### 3.1 已经做到的

- **跨联系人不可关联**：每个联系人独立 `SecretKey` + 独立 Endpoint；`local_id`
  只与一个对端绑定，mailbox 队列按 `local_id` 分类。
- **mailbox 不存发送方**：`StoredMessage` 只有 `(msg_id, to_peer_id, ciphertext)`，
  节点无法从存储里直接得到"谁发的"。
- **取回即删 + 同步删除**：消息被取走后广播 `sync_ack`，减少留存窗口。
- **内容双保险**：双棘轮 E2EE 之外，可再套洋葱；中继与终点 mailbox 都只见密文。
- **PoW**：抬高灌水成本（当前仅象征性，见 S3）。

### 3.2 各层能看到什么

| 位置 | 能看到 | 泄漏程度 |
|---|---|---|
| 传输层（n0 relay/DNS） | peer_id、连接时间、流量大小 | 中 |
| 首跳中继 | **上传者 TLS 身份** + 下一跳 | 高（若上传身份长期固定） |
| 中间中继 | 上一跳 + 下一跳 | 低 |
| 终点 mailbox | 上一跳 + 收件人队列 + 到达时间 | 中 |
| mailbox 数据库 | 收件人、msg_id、密文、时间 | 中 |
| 本地磁盘 | 加密库（SQLCipher） | 低（密码足够强时） |

### 3.3 关键风险：首跳身份

客户端投递时用的是**联系人专属身份**做 TLS 身份，因此首跳中继知道"这个专属
身份在给某队列发消息"。跨联系人不可关联，但**同一联系人下可长期关联**。

- 缓解：开启洋葱路由（首跳只看到一次性连接，如果客户端为每次发送换临时
  身份——CLI 已这样做，GUI 尚未）。
- 建议：GUI 也改为**每次发送用一次性 Endpoint 身份**，与 E2EE 身份解耦。

### 3.4 侧信道

- **长度**：包长 ≈ 载荷 + 94×跳数，能数出跳数、估计消息长短。
- **时序**：mailbox 记录到达时间；取回即删会产生"读取时间"。
- **序号**：`msg_id` 是 `gen:n`，节点能看出会话进度。

对抗方向：定长信元 + 随机填充、发送时间抖动、批量取回、msg_id 随机化
（排序改由客户端侧的 `(gen,n)` 完成）。

---

### 3.6 明文桶填充

消息在棘轮加密前先按桶对齐（`privchat-common::pad_plaintext`）：

```
明文 = "PPAD" | len(u32 BE) | payload | 零填充
总长 = 256 / 512 / 1K / 2K / … / 64K 中 ≥ payload+8 的最小桶
```

效果：同一桶内的不同长度消息，**密文长度完全一致**；接收端按 magic 截取，
旧版无头消息原样兼容。仍未覆盖的是**跳数**（洋葱层数会改变总长）与跨桶
的粗粒度差异——下一步是固定信元（所有包等长）。

### 3.7 gen0 绑定临时 eph（v5）

纯静态-静态 DH 派生 root0 的问题是：长期私钥一泄漏，**全部 gen0 消息**
（包括历史、包括单向会话里对方从不回复的那一整段）都能被离线解开。
v5 起 gen0 的两条方向链改为：

```
发送侧: ck = HKDF(root0, DH(eph_own, pk_peer))
接收侧: ck = HKDF(root0, DH(sk_own,  eph_peer))
```

临时 `eph` 每代一个、只出现在消息头里，私钥不落盘。于是攻击者仅凭长期
私钥拿不到 gen0 消息密钥。gen>=1 仍由 DH 刷新保证前向保密。

已知边界：**接收方**长期私钥泄漏时，攻击者可用 `DH(epk_peer, sk_own)`
还原接收侧绑定，gen0 仍会失守 —— 要补上需要 signed prekey（与 P0-3
的签名方案一起做）。消息格式版本随之升到 `PRR3/v5`，旧会话状态不兼容
（`from_bytes` 会按版本拒绝，双方重建会话）。

### 3.5 WebView 与打包层

- **CSP**：已配置 `default-src 'self'; script-src 'self'; style-src 'self'
  'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' ipc:
  http://ipc.localhost`，并用 Chromium 按同一策略加载构建产物验证，无违规。
- **安卓清单**：`android:allowBackup="false"`，避免通过 adb backup 导出应用
  数据目录（库本身是加密的，但备份会带走全部密文与元数据）。
- **权限**：capability 只开放 `core:default`、opener 与条码扫描所需项。

## 4. 加固建议（按投入产出排序）

1. **PoW 难度可配置**（S3）：节点在 `config.json` 里声明 `pow_bytes`，客户端
   按节点返回的难度重算；建议 2–3 字节。
2. **洋葱转发白名单**（S4）：已实现 `PRIVCHAT_MAILBOX_ONION_PEERS`，
   设置后只允许转发给列表中的节点；建议中继节点都开启。
3. **GUI 一次性上传身份**（3.3）：发送时临时生成 Endpoint，E2EE 身份不变。
4. **固定信元 + 填充**（S5）：所有包填充到同一长度，隐藏跳数与内容长度。
5. **部署层面**：role 分离（首跳 relay 与终点 mailbox 不同运营者）、
   自建 n0 relay、TTL 调短、日志脱敏。

---

## 5. 密码学参数速查

| 项 | 取值 |
|---|---|
| 消息加密 | ChaCha20-Poly1305（AEAD，头部作为 AAD） |
| 密钥交换 | X25519（Ed25519 身份转 Montgomery） |
| 棘轮 | 双棘轮，跳窗 200，skipped 池上限 1000；gen0 链绑定临时 eph（v5） |
| 洋葱层密钥 | HKDF-SHA256，info=`privchat/onion/key/v1`，AAD=`privchat/onion/v1` |
| 保险箱 KDF | PBKDF2-HMAC-SHA256，600,000 次，16B salt |
| 本地库 | SQLCipher（全库加密） |
| PoW | SHA-256 前导零字节，当前难度 1 |
| 明文填充 | `PPAD` + u32 长度，256B–64KB 二次幂桶 |

---

## 6. 依赖审计

`cargo audit`（RustSec 1403 条 advisory，677 个依赖）：

**审计发现的 8 个漏洞已全部通过升级修复**（`cargo update`）：

| crate | 原版本 → 新版本 | 问题 |
|---|---|---|
| ctutils | 0.4.2 → 0.4.8 | 掩码生成非恒定时间（影响密码学实现） |
| rustls | 0.23.43 → 0.23.46 | 证书解压内存放大 / 降级 / 握手跨加密层 / Debug 泄漏会话密钥 |
| rustls-webpki | 0.103.14 → 0.103.16 | 可能接受不受信任的中间证书 |
| webpki-roots / webpki-root-certs | 1.0.9 → 1.0.11 | 内置根证书包含已吊销的 emSign 中间证书 |

复跑结果：**0 vulnerabilities**。

剩余 15 条为警告（非漏洞）：部分 crate 标记 unmaintained（`atomic-polyfill`、
`paste`、`proc-macro-error`、`unic-*`、`glib`、`zvariant`）、`async-executor`
与 `chacha20 0.10.1` 被 yank、`tokio` 的 `AsyncFd` unsound（本项目未使用
`AsyncFd`）。`chacha20` 由 `chacha20poly1305` 锁定，后续跟上游升级。

复现：

```bash
cargo install cargo-audit --locked
cd privchat && cargo audit
```

## 7. 报告问题

发现安全问题时请附：复现步骤、影响范围、版本/commit。请勿在公开 issue 里
贴可直接利用的载荷；先私下联系维护者。
