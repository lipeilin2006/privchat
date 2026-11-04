# 洋葱中继配置（privchat-relay）

只做逐层剥离和转发：不落库、不解析内容、不存任何消息。
信箱（`privchat-mailbox`）是另一个程序，两者可以部署在不同机器上。

## config.json

`<data_dir>/config.json`，首次启动自动生成，已存在则绝不覆盖。
优先级：**环境变量 > config.json > 默认值**。

```json
{
  "bind": "0.0.0.0:8444",
  "onion_peers": []
}
```

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `bind` | 字符串 | 不设（随机端口） | 固定监听地址，如 `0.0.0.0:8444` |
| `onion_peers` | 字符串数组 | `[]`（不限制） | 允许转发的下一跳白名单（peer_id） |

## 环境变量

| 变量 | 对应字段 |
|---|---|
| `PRIVCHAT_RELAY_DATA_DIR` | 数据目录（只放 secret.key / config.json） |
| `PRIVCHAT_RELAY_BIND` | `bind` |
| `PRIVCHAT_RELAY_ONION_PEERS` | `onion_peers`（逗号分隔） |

## 行为

- 只挂 `privchat/onion` 一个 ALPN
- 剥一层；剩下还有下一跳 → 转发并把下游响应**原样**回传（中继不看内容）
- 自己就是终点 → 明确拒绝（终点必须是信箱）
- 下一跳不在白名单 → 拒绝

## 接口保护

| 项 | 值 |
|---|---|
| 并发连接上限 | 128（超出回 `relay busy`） |
| 单包上限 | 128 KB |
| 下游响应上限 | 32 MB |
| 单跳超时 | 90 秒 |
| 下一跳 | `onion_peers` 非空时只允许白名单 |

默认 `onion_peers` 为空 = 不限制，公开部署建议配上白名单。

## 启动输出

```
PrivChat Relay online
  peer_id : 9f2c...
  data_dir: /var/lib/privchat-relay
  bind    : 0.0.0.0:8444
```

把这个 `peer_id` 填到客户端「洋葱路由」的中继列表里。
