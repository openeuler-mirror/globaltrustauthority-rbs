# globaltrustauthority-rbs

[English](README.md) | 中文

**Resource Broker Service (RBS，资源代理服务)** 面向通过 [Global Trust Authority](https://gitcode.com/openeuler/global-trust-authority) 远程证明的工作负载，安全地下发密钥、证书及其他敏感资源。

## 概述

本仓库是一个 **Rust workspace**，用于策略驱动的可信资源分发。它整合了远程证明、访问策略评估、受保护资源获取、运维工具，以及面向机密计算与零信任环境的可部署服务打包。

包含：

- **`rbs`** — 代理服务，负责校验工作负载可信度、评估访问策略，并仅向通过证明的授权客户端下发受保护资源。
- **`rbc`** — 客户端 SDK 及可选命令行客户端，帮助应用提交证明证据、管理会话，并从 RBS 获取密钥、证书或其他受保护资源。
- **`rbs-cli`** — 运维工具，用于通过脚本或交互式 shell 管理代理用户、策略、资源、证书、令牌以及客户端侧校验流程。

## 快速开始

关于分步的搭建、构建、测试、运行与服务验证说明，参考 [`docs/build/build_and_install.md`](docs/build/build_and_install.md) 中的 [**快速开始**](docs/build/build_and_install.md#2-quick-start)。

## 文档

| 主题 | 位置 |
|------|------|
| AI 代理入门 | [AGENTS.md](AGENTS.md) |
| 系统架构 | [architecture.md](docs/design/architecture.md) |
| 构建、运行、测试 | [build_and_install.md](docs/build/build_and_install.md) |
| RPM 安装 | [rpm.md](docs/build/rpm.md) |
| RBC 客户端 CLI 用法 | [rbc.md](docs/usage_guide/rbc.md) |
| rbs-cli 用法 | [rbs_cli.md](docs/usage_guide/rbs_cli.md) |
| 容器部署 | [docker/](deployment/docker/) |
| REST API | [YAML](docs/proto/rbs_rest_api.yaml) · [MD](docs/api/rbs/md/rbs_rest_api.md) · [HTML](docs/api/rbs/html/rbs_rest_api.html) |
| 测试套件 | [README.md](tests/README.md) |
| 配置示例 | [rbs.yaml](rbs/conf/rbs.yaml) |
| 开发者工具 | [延伸阅读](docs/build/build_and_install.md#7-further-reading-and-tooling) |
| 贡献指南 | [CONTRIBUTING.md](CONTRIBUTING.md) |

## 许可证

基于 **木兰宽松许可证第2版（Mulan PSL v2）** 授权 — 详见 [LICENSE](LICENSE)。
