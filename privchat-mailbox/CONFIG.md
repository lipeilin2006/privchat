# 信箱 / 洋葱中继节点配置

节点（`privchat-mailbox`，同一个二进制，用 `role` 决定行为）只有**一个**配置文件：
`<data_dir>/config.json`。首次启动自动生成，已存在则绝不覆盖。

优先级：**环境变量 > config.json > 默认值**。
环境变量只是给 systemd / docker 临时覆盖用的，日常改配置只动 json。

`data_dir` 由 `PRIVCHAT_MAILBOX_DATA_DIR` 指定；未指定时取可执行文件所在目录。

## config.json

```json
{
  "ttl_secs": 604800,
  "role": "both",
  "bind": "0.0.0.0:8443",
  "onion_peers": [],
  "max_queue_msgs": 1000,
  "max_queue_bytes": 67108864,
  "max_queues": 50000
}
```

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `ttl_secs` | 整数 | `604800`（7 天） | 密文最长保留秒数；`0` = 永不过期 |
| `role` | 字符串 | `both` | `both` / `relay` / `mailbox`，见下表 |
| `bind` | 字符串 | 不设（随机端口） | 固定监听地址，如 `0.0.0.0:8443`；公网部署建议填 |
| `onion_peers` | 字符串数组 | `[]`（不限制） | 洋葱转发白名单：只允许把包转给这些 peer_id |
| `max_queue_msgs` | 整数 | `1000` | 单队列消息条数上限 |
| `max_queue_bytes` | 整数 | `67108864`（64 MiB） | 单队列总字节上限 |
| `max_queues` | 整数 | `50000` | 节点上队列总数上限（防刷 create） |

缺字段用默认值补；写坏了会打一行日志后按默认值启动，不会带病退出
（`role` 非法仍会直接报错，避免角色跑偏）。

## 角色

| role | 存取消息 | 转发洋葱 | 典型用途 |
|---|---|---|---|
| `both` | ✅ | ✅ | 单机 / 小规模部署 |
| `relay` | ❌（拒绝入站 mailbox 握手） | ✅ | 纯中继，不落库 |
| `mailbox` | ✅ | ❌（拒绝作为中间跳） | 只做存储终点 |

设计意图：**首跳中继与终点信箱应由不同运营者部署**，
否则同一个节点同时看到「发送方身份」和「收件人队列」，洋葱匿名性失效。

## 环境变量

| 变量 | 对应字段 |
|---|---|
| `PRIVCHAT_MAILBOX_DATA_DIR` | 数据目录（secret.key / mailbox.db / config.json） |
| `PRIVCHAT_MAILBOX_ROLE` | `role` |
| `PRIVCHAT_MAILBOX_TTL_SECS` | `ttl_secs` |
| `PRIVCHAT_MAILBOX_BIND` | `bind` |
| `PRIVCHAT_MAILBOX_ONION_PEERS` | `onion_peers`（逗号分隔） |
| `PRIVCHAT_MAILBOX_MAX_QUEUE_MSGS` | `max_queue_msgs` |
| `PRIVCHAT_MAILBOX_MAX_QUEUE_BYTES` | `max_queue_bytes` |
| `PRIVCHAT_MAILBOX_MAX_QUEUES` | `max_queues` |

## 节点之间还需要通信吗

队列协议下**不需要**：每条队列只属于一台信箱，客户端直接连这台节点读写，
不存在多副本，也就没有消息同步/补推/反熵。

跨节点通信只剩洋葱中继：`ONION_ALPN` 把剥离一层后的包转给下一跳（可选）。
旧的 `sync` / `sync_ack` / `put` / `fetch` / `peers` 操作、邻居表与 PEX、
以及 `mailboxes.json` 都已删除（老目录里的残留文件不再读取，可安全删除）。

## 客户端侧

- 每条队列绑定一台信箱；没配置信箱时无法建连接
- 每 500 条消息轮换入站队列，可换到另一台节点；旧队列排空后删除
- 选信箱和中继用同一套打分：`延迟 × 0.01 × 权重 + 优先级成本 × (1 − 权重)`

## 启动输出

```
PrivChat Mailbox online
  peer_id : c7a361b4...
  store   : /var/lib/privchat-mailbox/mailbox.db
  ttl     : 604800 secs (0 = never expire)
  data_dir: /var/lib/privchat-mailbox
  role    : both (mailbox=true, onion_relay=true)
  bind    : 0.0.0.0:8443
```

把 `peer_id` 填到客户端设置里的「信箱」或「洋葱路由」即可使用。
