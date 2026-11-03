# Mailbox 节点配置

节点启动时按以下优先级读取配置：

```
环境变量 > <data_dir>/config.json > 默认值
```

`data_dir` 由 `PRIVCHAT_MAILBOX_DATA_DIR` 指定；未指定时取可执行文件所在目录。

## config.json

首次启动会自动生成（缺失字段用默认值补全，已存在的文件不会被覆盖）：

```json
{
  "ttl_secs": 604800,
  "role": "both"
}
```

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `ttl_secs` | 整数 | `604800`（7 天） | 密文最长保留秒数；`0` = 永不过期 |
| `role` | 字符串 | `both` | `both` / `relay` / `mailbox`，见下表 |

非法 `role` 会在启动时直接报错退出，避免带病运行。

## 角色

| role | 存取消息 | 转发洋葱 | 典型用途 |
|---|---|---|---|
| `both` | ✅ | ✅ | 单机 / 小规模部署（向后兼容） |
| `relay` | ❌（拒绝入站 mailbox 握手） | ✅ | 纯中继，不落库 |
| `mailbox` | ✅ | ❌（拒绝作为中间跳） | 只做存储终点 |

P2 设计意图：**首跳中继与终点 mailbox 应由不同运营者部署**，
否则同一个节点同时看到「发送方身份」和「收件人队列」，洋葱匿名性失效。

## mailboxes.json

网格同步（节点间 `sync` / `sync_ack` 广播）的邻居列表：

```json
["<peer_id_1>", "<peer_id_2>"]
```

也可用环境变量 `PRIVCHAT_MAILBOX_PEERS="id1,id2"`（优先于文件）。

## 邻居自动扩充（PEX）

节点会**周期性**向已配置的邻居询问「你认识哪些 mailbox」，把新节点并入自己的
邻居表并写回 `mailboxes.json`，无需手工维护全网列表。

```
N1(只知道 N2) ──询问──> N2(认识 N1、N3) ──返回──> N1 学到 N3
```

| 项 | 说明 |
|---|---|
| 周期 | `PRIVCHAT_MAILBOX_PEX_SECS`，默认 `60` 秒（最小 5 秒） |
| 信任模型 | 只向**当前已知**节点询问，不接受陌生人主动推送；信任沿已有边扩散 |
| 过滤 | 只接受 64 位十六进制、非自身、未重复的 id |
| 上限 | 每节点最多 `64` 个邻居，防止无限膨胀 |
| 持久化 | 有新节点时重写 `mailboxes.json`，重启后保留 |
| 前置条件 | 对方必须是 mailbox/both 角色（relay-only 不接受 mailbox ALPN） |

### 同步与补推

- 客户端 `put` 成功后，节点立即向**全部已知邻居**广播 `Sync`（每条消息一个任务）
- 网络失败自动重试 3 次（0.5s / 1s 退避）；逻辑拒绝不重试
- PEX 学到新邻居时，会把本节点已有的最多 200 条消息**一次性补推**给它
- 环状拓扑靠 `(to_peer_id, msg_id)` 主键幂等去重截断，重复消息不再转发

> 仍缺：定期全量反熵（类似 Anti-Entropy），长时间离线的节点重连后只能拿到
> 新消息与补推窗口内的旧消息。

## 环境变量

| 变量 | 说明 |
|---|---|
| `PRIVCHAT_MAILBOX_DATA_DIR` | 数据目录（secret.key / mailbox.db / 配置文件） |
| `PRIVCHAT_MAILBOX_ROLE` | 覆盖 `config.json` 的 `role` |
| `PRIVCHAT_MAILBOX_TTL_SECS` | 覆盖 `config.json` 的 `ttl_secs` |
| `PRIVCHAT_MAILBOX_PEERS` | 覆盖 `mailboxes.json` |
| `PRIVCHAT_MAILBOX_PEX_SECS` | 邻居交换周期（秒），默认 60 |
| `PRIVCHAT_MAILBOX_ONION_PEERS` | 洋葱转发白名单（逗号分隔 peer_id）；未设则不限制 |

## 客户端侧

- 客户端可为每条消息设置「**最多成功推送节点数**」（默认 3，0 = 全部）：
  并发投递，达到目标成功数后中止其余请求
- 未配置任何 mailbox 时，发送会直接失败（P2P 直连已移除）

## 启动输出示例

```
PrivChat Mailbox online
  peer_id : c7a361b4...
  store   : /tmp/pmb3/mailbox.db
  ttl     : 604800 secs (0 = never expire)
  data_dir: /tmp/pmb3
  role    : mailbox (mailbox=true, onion_relay=false)
  peers   : (none) — 单节点模式
```

把 `peer_id` 填到客户端设置里的「Mailbox」或「洋葱路由」即可使用。
