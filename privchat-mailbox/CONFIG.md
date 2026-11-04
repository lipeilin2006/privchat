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

## 节点之间还需要通信吗

队列协议下**不需要**：每条队列只属于一台 mailbox，客户端直接连这台节点读写，
不存在多副本，也就没有消息同步/补推/反熵。

跨节点通信只剩两种用途：

- **洋葱中继**：`ONION_ALPN` 把剥离一层后的包转给下一跳（可选功能）；
- 无需 PEX：客户端按邀请里的 peer_id/票据直连，不依赖邻居表发现。

旧的 `sync` / `sync_ack` / `put` / `fetch` / `peers` 操作、邻居表与 PEX、
以及 `mailboxes.json` 配置都已删除（老目录里残留的文件不再读取，可安全删除）。

## 环境变量

| 变量 | 说明 |
|---|---|
| `PRIVCHAT_MAILBOX_DATA_DIR` | 数据目录（secret.key / mailbox.db / 配置文件） |
| `PRIVCHAT_MAILBOX_ROLE` | 覆盖 `config.json` 的 `role` |
| `PRIVCHAT_MAILBOX_TTL_SECS` | 覆盖 `config.json` 的 `ttl_secs` |
| `PRIVCHAT_MAILBOX_ONION_PEERS` | 洋葱转发白名单（逗号分隔 peer_id）；未设则不限制 |

单队列限额（默认 1000 条 / 64 MiB）与节点队列总数上限（默认 5 万）
写在代码里；`open_with_limits` 供测试与自建运营自定义。

## 客户端侧

- 每条队列绑定一台 mailbox；未配置 mailbox 时无法建连接
- 每 500 条消息轮换入站队列，可换到另一台节点；旧队列排空后删除

## 启动输出示例

```
PrivChat Mailbox online
  peer_id : c7a361b4...
  store   : /tmp/pmb3/mailbox.db
  ttl     : 604800 secs (0 = never expire)
  data_dir: /tmp/pmb3
  role    : mailbox (mailbox=true, onion_relay=false)
```

把 `peer_id` 填到客户端设置里的「Mailbox」或「洋葱路由」即可使用。
