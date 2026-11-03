# PrivChat

端到端加密聊天。消息统一经 mailbox 节点投递（P2P 直连已移除），可选洋葱路由多层转发；双棘轮（Double Ratchet）提供前向保密，SQLCipher 加密全部本地数据。

## 仓库结构

```
privchat-client/       Tauri 客户端（Android / Windows / macOS）
  src/                 Vue 3 + Quasar 前端
  src-tauri/           Rust 后端（L2 应用层 / L2.5 加密 / L3 传输 / L4 封装）
privchat-common/       共享 crate：mailbox wire 协议与 PoW
privchat-mailbox/      离线消息缓存节点（可网格组网同步）
privchat-onion/        洋葱路由：多层封装 / 逐跳剥离
privchat-cli/          命令行测试客户端（文本 / 图片 / 洋葱路径）
```

## 安全模型

- **无主身份**：每个联系人使用独立 SecretKey + 独立 iroh Endpoint，跨联系人不关联。
- **双棘轮加密**：每条消息独立密钥，发送失败不推进链；接收方跳过窗口可自愈乱序。
- **本地加密存储**：SQLCipher 全库加密，密码解锁保险箱（vault）。
- **统一投递**：所有消息经 mailbox 节点（可网格同步，取回即删）；发送端不再尝试直连对端。
- **洋葱路由（可选）**：多层加密逐跳转发，最后一跳为 mailbox 节点；中继看不到完整路径与明文。

## 开发

### 一键构建脚本（`scripts/`）

```bash
bash scripts/build-windows-x86_64.sh          # Windows 桌面客户端 -> target/windows-x86_64/
bash scripts/build-linux-x86_64.sh            # Linux 桌面客户端 -> target/linux-x86_64/
bash scripts/build-android-arm64.sh           # Android arm64 APK -> target/android-arm64/
```

各脚本要求对应平台的完整工具链（Rust / Node / Tauri CLI；Android 额外需 SDK、NDK、JDK），自动探测 `ANDROID_HOME`/`ANDROID_NDK_HOME` 等环境，产物统一归档到工作区 `target/` 目录。可选参数：`--mailbox`（一并构建 mailbox 节点）、`--sign <keystore> <alias> <pass>`（签名 APK）。

### 桌面端（Windows）

```powershell
cd privchat-client
npm install
npm run tauri build -- --no-bundle
```

### Android（arm64）

```bash
npm run tauri android build -- --target aarch64 --apk --ci
```

或直接使用 `scripts/build-android-arm64.sh`（自动探测 SDK/NDK）。

### mailbox 节点

```bash
cd privchat-mailbox
cargo run --release
```

首次启动自动生成 `config.json` / `mailboxes.json` / `secret.key`。角色（`both`/`relay`/`mailbox`）与 TTL 可在 `config.json` 配置，详见 [privchat-mailbox/CONFIG.md](privchat-mailbox/CONFIG.md)。

## 测试

```bash
cargo test                      # 根工作区（client lib + mailbox）
```

## License

[MIT](LICENSE)