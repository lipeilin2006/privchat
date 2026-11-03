# privchat-cli

PrivChat 的命令行测试客户端。复用客户端真实的 `Ratchet`（双棘轮）加密模块
和 `privchat-common` 的 mailbox wire 协议，在没有 GUI 的服务器上验证：

```text
身份 -> 双棘轮加密 -> [洋葱多层封装 -> 逐跳中继] -> mailbox PUT
身份 -> mailbox FETCH -> 双棘轮解密 -> 文本 / 图片重组
```

## 快速开始

```bash
# 1) 起节点（P2 角色分离：relay 只转发，mailbox 只存取）
PRIVCHAT_MAILBOX_DATA_DIR=/tmp/pmb1 PRIVCHAT_MAILBOX_ROLE=relay   ./target/debug/privchat-mailbox
PRIVCHAT_MAILBOX_DATA_DIR=/tmp/pmb2 PRIVCHAT_MAILBOX_ROLE=relay   ./target/debug/privchat-mailbox
PRIVCHAT_MAILBOX_DATA_DIR=/tmp/pmb3 PRIVCHAT_MAILBOX_ROLE=mailbox ./target/debug/privchat-mailbox
# 记下各自的 peer_id

# 2) 建主身份
export PRIVCHAT_CLI_HOME=/tmp/pcli
privchat-cli init alice
privchat-cli init bob
```

## 身份模型（P1：每联系人一个身份）

主身份只用于本机管理；**每个联系人再派生一份专属身份**，互相交换后使用：

```bash
# bob 为 alice 派生专属身份，把打印出的 peer_id（B_a）发给 alice
privchat-cli derive bob alice

# alice 登记 B_a，再为 bob 派生专属身份（A_b），把 A_b 发给 bob
privchat-cli contact alice bob <B_a>
privchat-cli derive alice bob

# bob 登记 A_b
privchat-cli contact bob alice <A_b>

# 之后 alice 直接按 label 发送
privchat-cli send alice bob "你好" --mailbox <mailbox_peer>
privchat-cli recv bob --mailbox <mailbox_peer>
```

- 身份文件：`<name>@<label>.id`
- 会话文件：`<name>@<peer_id>.ratchet`
- 联系人文件：`<name>.contacts`，每行 `<label> <peer_id>`
- 没派生专属身份时自动退回主身份（兼容旧用法）

## 连接身份（P0：一次性）

发送侧每次命令都用 `SecretKey::generate()` 新建 Endpoint：

- 首跳中继看到的是**一次性 id**，不是发送方长期身份
- 双棘轮身份与传输身份彻底解耦
- 接收侧 `fetch` 仍必须用队列所属身份（这是 mailbox 的归属校验）

## 洋葱路由

```bash
privchat-cli send alice bob "hi" --mailbox <N3> --relay <N1>,<N2>,<N3>
```

- 每层：`eph_pub(32) || nonce(12) || AEAD(next(32) || len(2) || inner)`
- 中继剥离一层后只看到「下一跳 + 剩余密文」
- 终点把最内层请求交给 mailbox（只允许匿名 `put`）

## 节点角色（P2）

| `PRIVCHAT_MAILBOX_ROLE` | 行为 |
|---|---|
| `both`（默认） | 既存取又转发 |
| `relay` | 只转发洋葱；作为终点会被拒绝 |
| `mailbox` | 只存取；作为中间跳会拒绝转发 |

这样「首跳中继」和「终点 mailbox」可以由不同运营者部署，避免单点同时
看到发送方与收件方。

## 状态文件（P3）

`.ratchet` 文件带固定头：

```text
"PRST" | version(1) | owner_pub(32) | ratchet_state
```

- 载入时校验 magic、版本与归属身份；**copy 到别的身份下会直接拒绝**
- 校验入口：`privchat-cli state <name> <label>`

## 图片发送

```bash
privchat-cli send-image alice bob ./photo.png \
  --mailbox <mailbox> [--relay N1,N2] [--chunk 8192]

privchat-cli recv-image bob --mailbox <mailbox> [--peer <label>] [--out ./got.png]
```

先发 `img-manifest`（名/大小/sha256/分块数），再逐块发原始字节；接收端按
`(gen,n)` 排序重组并校验 sha256。

## 子命令

| 命令 | 说明 |
|---|---|
| `init <name>` | 生成主身份 |
| `id <name>` | 打印主身份 peer_id |
| `derive <name> <label>` | 为联系人生成专属身份 |
| `contact <name> <label> [peer_id]` | 登记联系人（省略 peer_id 时 label 即 peer_id） |
| `state <name> <label>` | 校验状态文件归属 |
| `ls` | 列出本地身份与会话 |
| `ping <mailbox>` | 探活 mailbox |
| `send <from> <to> <text> --mailbox <peer> [--relay ...]` | 发送文本 |
| `recv <name> --mailbox <peer> [--peer <label>]` | 拉取并解密 |
| `send-image` / `recv-image` | 图片收发 |
| `demo <mailbox>` | 端到端自测 |

## 安全边界与已知限制

- 洋葱是**单向**的：没有匿名回程，终点只能 `put`
- 没有定长分片/填充，包长会暴露跳数与载荷大小
- 没有守卫节点与路径策略，恶意中继可做流量关联
- 中继在响应后延迟关闭连接，规避 QUIC 关闭丢弃未读流数据的问题
- `fetch` 取回即删，图片分块需一次拉完；乱序窗口受 `MAX_SKIP=200` 限制

## 实现说明

- 加密：`privchat_client_lib::layers::crypto::Ratchet`
- 洋葱：`privchat-onion` crate（`wrap` / `peel`，含单测）
- 投递：`privchat_common::{find_pow, make_endpoint, send_request}`
- 依赖 iroh 的 n0 发现/中继；每次命令重新建 Endpoint，单次 3–10 秒属正常
