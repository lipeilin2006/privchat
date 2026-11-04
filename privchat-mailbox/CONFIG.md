# 信箱节点配置（privchat-mailbox）

信箱和洋葱中继现在是**两个独立的程序**：

| 程序 | 干什么 | 配置 |
|---|---|---|
| `privchat-mailbox` | 存队列、收发密文；同时作为洋葱**终点**收最内层 | `data_dir/config.json` |
| `privchat-relay` | 只剥一层、转下一跳；不落库、不解析内容 | 见 [privchat-relay/CONFIG.md](../privchat-relay/CONFIG.md) |

> 旧配置里 `role=both` 仍能启动（等价于 mailbox），写 `role=relay` 会直接报错
> 并提示改用 `privchat-relay`。

## config.json

`<data_dir>/config.json`，首次启动自动生成，已存在则绝不覆盖。
优先级：**环境变量 > config.json > 默认值**。

```json
{
  "ttl_secs": 604800,
  "bind": "0.0.0.0:8443",
  "max_queue_msgs": 1000,
  "max_queue_bytes": 67108864,
  "max_queues": 50000
}
```

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `ttl_secs` | 整数 | `604800`（7 天） | 密文最长保留秒数；`0` = 永不过期 |
| `bind` | 字符串 | 不设（随机端口） | 固定监听地址，如 `0.0.0.0:8443` |
| `max_queue_msgs` | 整数 | `1000` | 单队列消息条数上限 |
| `max_queue_bytes` | 整数 | `67108864`（64 MiB） | 单队列总字节上限 |
| `max_queues` | 整数 | `50000` | 节点上队列总数上限 |

缺字段用默认值补；写坏了打一行日志后按默认值启动。

## 环境变量

| 变量 | 对应字段 |
|---|---|
| `PRIVCHAT_MAILBOX_DATA_DIR` | 数据目录（secret.key / mailbox.db / config.json） |
| `PRIVCHAT_MAILBOX_BIND` | `bind` |
| `PRIVCHAT_MAILBOX_TTL_SECS` | `ttl_secs` |
| `PRIVCHAT_MAILBOX_MAX_QUEUE_MSGS` | `max_queue_msgs` |
| `PRIVCHAT_MAILBOX_MAX_QUEUE_BYTES` | `max_queue_bytes` |
| `PRIVCHAT_MAILBOX_MAX_QUEUES` | `max_queues` |

`PRIVCHAT_MAILBOX_ROLE` 仍可识别：`mailbox`/`both` 都当信箱，`relay` 报错。

## 信箱节点做什么

- 接受 `privchat/mailbox` 的队列请求：建队列 / 投递 / 取走 / 删除
- 写权限靠 sender 公钥验签，读权限靠 owner 公钥验签
- 接受洋葱 `ONION_ALPN` 的**最内层**包（它是路径终点），转发一律拒绝
- 只存密文，解不开内容；消息按 TTL 清理

## 启动输出

```
PrivChat Mailbox online
  peer_id : c7a361b4...
  store   : /var/lib/privchat-mailbox/mailbox.db
  ttl     : 604800 secs (0 = never expire)
  data_dir: /var/lib/privchat-mailbox
  role    : mailbox (onion terminal only; 中继请用 privchat-relay)
  bind    : 0.0.0.0:8443
```

把 `peer_id` 填到客户端设置里的「信箱」即可；`privchat-relay` 的 peer_id 填到「洋葱路由」。
