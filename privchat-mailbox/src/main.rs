//! PrivChat mailbox 节点可执行入口：配置来自环境变量 / 数据目录。

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    privchat_mailbox::node::run().await
}
