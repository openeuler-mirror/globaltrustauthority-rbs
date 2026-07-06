# 贡献指南

感谢您参与 **globaltrustauthority-rbs** 项目的贡献！我们欢迎并感谢各种形式的贡献——缺陷修复、新功能、文档改进、提供者实现以及测试。遵循本指南有助于确保评审流程顺畅高效。

---

### 开始之前

1. **检索已有工作**
   先查看本仓库的 issue 与 merge request，确认是否已有人在处理相同想法或问题。

2. **大型变更先讨论**
   对于重大变更或新功能，请先开 issue 与维护者讨论设计、范围与实现方案。RBS 具有强安全不变量（见 [`AGENTS.md` § 安全不变量](AGENTS.md#security-invariants) 与 [`docs/design/architecture.md` §10](docs/design/architecture.md#10-security-architecture)）；凡涉及远程证明、策略评估、JWE 边界或公开中间件路径的变更，设计对齐尤为重要。

3. **阅读代理与规范指南**
   [`AGENTS.md`](AGENTS.md) 记录了 workspace 布局、模块可见性、命名、日志、OpenAPI schema 以及每项变更必须遵守的安全不变量。

---

### 如何贡献

按以下步骤准备并提交您的贡献。

### 1. Fork 与克隆

先将仓库 fork 到您的 GitCode 账号，并在本地克隆：

```bash
git clone git@gitcode.com:<your-username>/globaltrustauthority-rbs.git
cd globaltrustauthority-rbs
```

### 2. 搭建项目

构建说明见 [`docs/build/build_and_install.md`](docs/build/build_and_install.md)（§2 快速开始是最快路径；§1 列出完整依赖，含 `pkg-config`、`libssl-dev` 及相关包）。最低前置要求：

- **Linux** `x86_64` 或 `aarch64`（macOS/Windows 非主平台；可用 **WSL2** 或见 build 文档 §5 容器流程）
- **Rust** stable 工具链（若 `cargo build` 报 `Cargo.lock` 错误，请用 [rustup](https://rustup.rs/)）
- `openssl`、`git`（构建与 RBS e2e 所需；git 为 `GIT_HASH` 嵌入所需）
- **cargo-deny**（运行 §4 中的 `cargo deny check` / `cargo deny-all` 前需安装；合并门本身不包含此项）
- **Node.js** >= 22.12（经 `./scripts/generate-api-docs.sh` 生成 API 文档；合并门 OpenAPI 检查仅比对 YAML，不调用 Node）
- Python 3 + `tests/requirements.txt` 中的包（`pytest`、`httpx`、`PyYAML`）（e2e 层）：

  `python3 -m pip install -r tests/requirements.txt`

### 3. 创建分支

创建一个描述性强的新分支，使用推荐前缀之一：

- `feature/` 新功能。
- `fix/` 缺陷修复。
- `chore/` 维护或构建相关。
- `docs/` 仅文档变更。
- `test/` 仅测试变更。

```bash
git checkout -b feature/your-feature-name
```

### 4. 修改代码

**聚焦单一关注点：** 尽可能让变更只围绕一个主题。

**遵守规范：** 遵循 [`AGENTS.md` § 代码规范](AGENTS.md#code-conventions) 中的编码风格与约定，特别注意：

- 运行 `cargo fmt`——格式由 [`rustfmt.toml`](rustfmt.toml) 控制（edition 2021、`max_width = 120`、4 空格、Unix 换行）。
- 运行 `cargo clippy`（或 `cargo clippy-all`，若可用）并清理警告。
- 运行 `cargo deny check`（或 `cargo deny-all`）——许可证/安全公告策略由 [`deny.toml`](deny.toml) 强制；本项目为木兰 PSL v2。以上 clippy/deny 步骤属于**质量门**，合并门 `test_all.sh` 不会自动运行它们（见 §7）。
- 遵守模块可见性规则：`rbs/rest/src/lib.rs` 仅为集成测试暴露 `routes`、`server`、`middleware`；不得扩大各 crate 已有可见性之外的范围。
- 使用 `log` crate facade（`error!` … `trace!`）；**不要**在请求热路径上调用 `log::logger().flush()`。
- 注释应谨慎添加，仅在阐明非显而易见的行为时使用；保持公开 API 文档最新——与周围代码风格保持一致。
- **语言要求：** 提交信息、代码注释与文档必须使用英文；本双语 `CONTRIBUTING.md` 除外。

**文档化代码：** 保持公开 API 有文档。REST 端点变更时更新 OpenAPI 注解；RBC SDK / `rbc-cli` 或 `rbs-cli` 行为变更时同步更新 §6 所列用法指南与（如适用）SDK 参考；架构、构建流程、维护者约定变更时同步更新 §6 所列项目文档。

**保持一致性：** 确保文档、注释与代码实现保持一致——涵盖 `AGENTS.md`、`docs/`、`tests/` 下的说明文档、测试代码、构建脚本、部署配置及相关文档。任何行为变更须同步更新所有相关产物；不得留下与代码不符的过时文档或注释。

### 5. 新增或更新测试

RBS 有两层测试，请在对应层覆盖您的变更：

| 层级 | 运行器 | 位置 |
|------|--------|------|
| Rust 单元/集成 | `cargo test` | 各 crate 的 `tests/`（如 `rbs/core/tests/`、`rbs/rest/tests/`） |
| 黑盒 e2e | `pytest`、`httpx`、`PyYAML`（`tests/requirements.txt`） | `tests/e2e/<suite>/`（`rbs`、`rbc`、`tools` 标记） |

优先使用公开 API 与 crate 内 `#[cfg(test)]` 模块。

- **RBS（`rbs`）**：新增端点或行为变更应在 `tests/e2e/rbs/` 下增补或更新 e2e 用例（见 [`tests/e2e/rbs/README.md`](tests/e2e/rbs/README.md)）。
- **RBC SDK / `rbc-cli`（`rbc`）**：在 `rbc/tests/` 增补或更新 Rust 测试；适用时在 `tests/e2e/rbc/` 增补 e2e。
- **`rbs-cli` / admin client（`tools`）**：在 `tools/` 各 crate 的 `tests/` 增补或更新 Rust 测试；适用时在 `tests/e2e/tools/` 增补 e2e。

合并门可按组件缩小范围：`./tests/test_all.sh --suite rbc` 或 `--suite tools`（见 [`tests/README.md`](tests/README.md)）。断言放在 `test_*.py` 中，而非 `helpers/`。

### 6. 必要时同步文档

按变更所在组件更新文档：

#### REST API（`rbs`）

若新增或修改 API 端点或参数：

1. 更新 `rbs/rest/src/routes/` 中的路由 handler。
2. 更新 OpenAPI 注解（`#[utoipa::path]`、`#[derive(ToSchema)]`）。
3. 重新生成：

   ```bash
   ./scripts/generate-api-docs.sh
   ```

4. 提交重新生成的 `docs/proto/rbs_rest_api.yaml`、`docs/api/rbs/md/rbs_rest_api.md`、`docs/api/rbs/html/rbs_rest_api.html`。

> `test_all.sh` 的 OpenAPI 检查只比对 YAML。CI（`CI=true`）下 `./scripts/generate-api-docs.sh` 还会校验 `docs/api/rbs/` 下 Markdown/HTML 是否同步；仅更新 YAML 可能导致流水线失败。

#### RBC SDK / `rbc-cli`（`rbc`）

- 行为、配置、`rbc-cli` 参数变更：更新 [`docs/usage_guide/rbc.md`](docs/usage_guide/rbc.md)。
- 公开 SDK 类型或 FFI 面变更：运行 `python3 scripts/gen-rbc-sdk-docs.py`，提交 `docs/api/rbc/sdk.md`。

#### `rbs-cli` / admin client（`tools`）

- 命令、子命令、flag 或环境变量变更：更新 [`docs/usage_guide/rbs_cli.md`](docs/usage_guide/rbs_cli.md)。

#### 项目与维护者文档

按变更类型更新对应文档，并与代码、`scripts/`、生成产物保持一致：

| 变更类型 | 更新位置 |
|----------|----------|
| AI/贡献者速查、workspace 布局、命名、安全不变量摘要 | [`AGENTS.md`](AGENTS.md)（保持简短；流程细节放在本文件与 `docs/`，避免重复长文） |
| 架构、组件边界、运行时流程、威胁模型 | [`docs/design/architecture.md`](docs/design/architecture.md)（安全相关内容与 `AGENTS.md` § 安全不变量一致） |
| 本地构建、安装、容器、RPM | [`docs/build/build_and_install.md`](docs/build/build_and_install.md)、[`docs/build/rpm.md`](docs/build/rpm.md) |
| 仓库入口与快速链接 | [`README.md`](README.md) |
| 合并门、e2e 套件、夹具约定 | [`tests/README.md`](tests/README.md)、[`tests/e2e/rbs/README.md`](tests/e2e/rbs/README.md) 等 |
| 贡献流程本身 | 本文件 [`CONTRIBUTING.md`](CONTRIBUTING.md)（**中英文同步**） |

上述维护者文档（除本文件外）须使用**英文**。仅改文档时，在 MR 中说明已核对文中命令、路径与依赖是否与仓库一致。

### 7. 运行合并门

**合并门**（提交前必须通过）：`./tests/test_all.sh` 依次运行 Cargo workspace 测试、OpenAPI **YAML** 漂移检查、pytest e2e。它**不**运行 `cargo clippy` 或 `cargo deny check`。

```bash
# 默认：Cargo workspace 测试 + OpenAPI YAML 漂移 + pytest e2e
./tests/test_all.sh
```

**API 变更（`rbs`）：** 除合并门外，还须按 §6 运行 `./scripts/generate-api-docs.sh`，并提交 YAML、Markdown 与 HTML 全部产物。

**SDK / CLI 变更（`rbc`、`tools`）：** 按 §6 更新用法指南与（如适用）`docs/api/rbc/sdk.md`；运行 `./tests/test_all.sh --suite rbc` 或 `--suite tools`（或对应 crate 的 `cargo test -p …`）。

**仅文档变更：** 使用 `docs/` 分支前缀；提交信息如 `docs(architecture):`、`docs(build):`、`docs(agents):`。未改 Rust/脚本/生成产物时可不新增测试；在 MR 中说明已按文档核对命令与路径。若同期包含代码变更，仍须完整合并门。

**质量门**（§4；请在合并前于本地执行；流水线可能另有检查）：

```bash
cargo fmt
cargo clippy-all    # 或 cargo clippy
cargo deny-all      # 或 cargo deny check
```

仅 Rust 的快速迭代：

```bash
cargo test --workspace
cargo test -p rbs-core
cargo test -p rbs-rest
cargo test -p rbc
cargo test -p rbs-cli
```

仅 e2e，或缩小合并门范围（详见 [`tests/README.md`](tests/README.md) 与 [`AGENTS.md`](AGENTS.md) Testing）：

```bash
./tests/run_e2e.sh --suite rbs
./tests/run_e2e.sh --suite rbc
./tests/run_e2e.sh --suite tools
ENABLE_E2E_TESTS=0 ./tests/test_all.sh      # 跳过 e2e
./tests/test_all.sh --suite rbs               # RBS Cargo 包 + rbs e2e
./tests/test_all.sh --suite rbc               # rbc Cargo + rbc e2e
./tests/test_all.sh --suite tools             # tools Cargo + tools e2e
```

**要求：** 合并前必须通过合并门（`./tests/test_all.sh`）。

### 8. 提交变更

提交信息须清晰、简洁、具描述性，采用 [Conventional Commits](https://www.conventionalcommits.org/) 风格并带 scope，与现有历史一致（如 `fix(rbs):`、`feat(rbc):`、`fix(tools):`、`docs(architecture):`、`docs(build):`、`docs(agents):`、`docs(tests):`、`test(tools):`）。

本仓库在 GitCode 合入 Merge Request 后，提交历史可能出现 `!NN` 前缀（如 `!54`）或 `See merge request: …!NN`——由平台自动添加。请勿在分支名或 commit message 中手动写入 `!NN`。

示例：

```bash
git add .
git commit -m "fix(rbs): handle null provider in ResourceService (fixes #42)"
```

### 9. 推送变更

将新分支推送到您 fork 的仓库：

```bash
git push origin feature/your-feature-name
```

### 10. 创建 Merge Request (MR)

从您 fork 的分支向主仓库的目标分支（通常为 `master`）发起 merge request。

**详细描述：** 包含变更的完整描述、理由以及相关 issue 编号（如 Closes #101）。若变更影响 [`AGENTS.md` § 安全不变量](AGENTS.md#security-invariants) 中的不变量，请显式说明。

**检查清单：** 建议在 MR 描述中加入如下小型清单：

合并门：

- [ ] `./tests/test_all.sh` 通过
- [ ] API 变更（`rbs`）：已按 §6 运行 `generate-api-docs.sh` 并提交全部产物
- [ ] SDK / CLI 变更（`rbc`、`tools`）：已按 §6 更新用法指南与（如适用）`docs/api/rbc/sdk.md`

质量门（§4）：

- [ ] `cargo fmt` 已执行
- [ ] `cargo clippy` 通过
- [ ] `cargo deny check` 通过

其他：

- [ ] 已新增/更新测试
- [ ] 维护者/架构/构建文档（`AGENTS.md`、`docs/design/`、`docs/build/`、`README.md` 等）：已按 §6 更新且与代码/脚本一致
- [ ] 未提交任何密钥

### 11. 合并前

- 确保所有 CI 检查通过（本地 `./tests/test_all.sh`、§4 质量门，以及流水线检查）。
- 确保该 Merge Request 至少由项目两名维护者评审。
- 采纳所有评审意见。若意见冲突，请安排会议、在所有评审者之间协调达成共识。
- 此后方可请维护者合并该 Merge Request。

### 语言

本文档以中英文双语表述，中英文版本具有同等效力。如果中英文版本存在任何冲突或不一致，以英文版为准。

---

# Contributing

Thank you for your interest in contributing to **globaltrustauthority-rbs**! We welcome
all kinds of contributions, including bug fixes, new features, documentation
improvements, provider implementations, and tests. Following this guide helps keep
the review process smooth and efficient.

---

### Before You Start

1. **Search Existing Work**
   Check the repository issues and merge requests first to see whether someone
   is already working on the same idea or problem.

2. **Discuss Large Changes**
   For major changes or new features, open an issue first and discuss the design,
   scope, and implementation plan with the maintainers. RBS has strict security
   invariants (see [`AGENTS.md` § Security Invariants](AGENTS.md#security-invariants)
   and [`docs/design/architecture.md` §10](docs/design/architecture.md#10-security-architecture));
   design alignment is especially important for changes that touch attestation,
   policy evaluation, the JWE boundary, or the public middleware paths.

3. **Read the Agent & Conventions Guide**
   [`AGENTS.md`](AGENTS.md) documents the workspace layout, module visibility,
   naming, logging, OpenAPI schema, and security invariants that every change
   must respect.

---

### How to Contribute

Use the following steps to prepare and submit your contribution.

### 1. Fork & Clone

Fork the repository to your GitCode account, then clone it locally:

```bash
git clone git@gitcode.com:<your-username>/globaltrustauthority-rbs.git
cd globaltrustauthority-rbs
```

### 2. Set Up the Project

See [`docs/build/build_and_install.md`](docs/build/build_and_install.md) for build
instructions. §2 provides the quickest path to get started, and §1 lists the
full dependency set, including `pkg-config`, `libssl-dev`, and related packages. Minimum
prerequisites:

- **Linux** `x86_64` or `aarch64` (macOS and Windows are not primary hosts; use
  **WSL2** or the container workflow in the build guide §5)
- **Rust** stable toolchain (use [rustup](https://rustup.rs/) if `cargo build`
  complains about `Cargo.lock`)
- `openssl` and `git` (required for builds and RBS e2e tests; git is also used
  to embed `GIT_HASH`)
- **cargo-deny** (install it before running `cargo deny check` / `cargo deny-all`
  in §4; the merge gate does not run this step)
- **Node.js** >= 22.12 (used by `./scripts/generate-api-docs.sh`; the merge gate
  only checks OpenAPI YAML drift and does not invoke Node)
- Python 3 + packages from `tests/requirements.txt` (`pytest`, `httpx`, `PyYAML`)
  for the e2e layer:

  `python3 -m pip install -r tests/requirements.txt`

### 3. Create a Branch

Create a descriptively named branch for your work. Use one of these recommended
prefixes:

- `feature/` for new features.
- `fix/` for bug fixes.
- `chore/` for maintenance or build-related tasks.
- `docs/` for documentation-only changes.
- `test/` for test-only changes.

```bash
git checkout -b feature/your-feature-name
```

### 4. Make Changes

**Keep it Focused:** Keep each change focused on one concern whenever possible.

**Adhere to Standards:** Follow the project's coding style and conventions
documented in [`AGENTS.md` § Code Conventions](AGENTS.md#code-conventions).
In particular:

- Run `cargo fmt` — formatting is governed by [`rustfmt.toml`](rustfmt.toml)
  (edition 2021, `max_width = 120`, 4 spaces, Unix newlines).
- Run `cargo clippy` (or `cargo clippy-all` if available) and resolve warnings.
- Run `cargo deny check` (or `cargo deny-all`) — license/advisory policy is
  enforced via [`deny.toml`](deny.toml); the project is Mulan PSL v2. These
  clippy and cargo-deny steps are **quality gates**; the merge gate `test_all.sh` does not
  run them automatically (see §7).
- Respect module visibility rules: `rbs/rest/src/lib.rs` exposes `routes`,
  `server`, and `middleware` for integration tests; do not widen visibility
  beyond what each crate already exposes.
- Use the `log` crate facade (`error!` … `trace!`); do **not** call
  `log::logger().flush()` on per-request hot paths.
- Add comments sparingly and only when they clarify non-obvious behavior; keep
  public API docs current and match the surrounding code style.
- **Language Requirement:** Commit messages, code comments, and documentation
  must be written in English, except for this bilingual `CONTRIBUTING.md`.

**Document Code:** Keep public APIs documented. Update OpenAPI annotations when
REST endpoints change. Update the usage guides and SDK reference listed in §6
when RBC SDK, `rbc-cli`, or `rbs-cli` behavior changes. Update the project docs
listed in §6 when architecture, build workflow, or maintainer conventions change.

**Keep Consistent:** Ensure documentation, comments, and code implementation
stay consistent across `AGENTS.md`, docs under `docs/` and `tests/`, test code,
build scripts, deployment configs, and related artifacts. Any behavioral change
must update all relevant artifacts in the same change. Do not leave stale docs
or comments that disagree with the code.

### 5. Add or Update Tests

RBS has two test layers. Cover your change in the appropriate layer:

| Layer | Runner | Location |
|-------|--------|----------|
| Rust unit / integration | `cargo test` | Per-crate `tests/` (e.g. `rbs/core/tests/`, `rbs/rest/tests/`) |
| Black-box e2e | `pytest`, `httpx`, `PyYAML` (`tests/requirements.txt`) | `tests/e2e/<suite>/` (`rbs`, `rbc`, `tools` markers) |

Prefer public APIs and in-crate `#[cfg(test)]` modules.

- **RBS (`rbs`)**: Add or update e2e cases under `tests/e2e/rbs/` for new
  endpoints or behavior changes (see [`tests/e2e/rbs/README.md`](tests/e2e/rbs/README.md)).
- **RBC SDK / `rbc-cli` (`rbc`)**: Add or update Rust tests under `rbc/tests/`;
  add e2e under `tests/e2e/rbc/` when applicable.
- **`rbs-cli` / admin client (`tools`)**: Add or update Rust tests under each
  `tools/` crate's `tests/`; add e2e under `tests/e2e/tools/` when applicable.

You can narrow the merge gate by component: `./tests/test_all.sh --suite rbc` or
`--suite tools` (see [`tests/README.md`](tests/README.md)). Assertions belong in
`test_*.py`, not in `helpers/`.

### 6. Sync Documentation When Needed

Update the documentation for the component you changed:

#### REST API (`rbs`)

If you add or modify API endpoints or parameters:

1. Update route handlers in `rbs/rest/src/routes/`.
2. Update OpenAPI annotations (`#[utoipa::path]`, `#[derive(ToSchema)]`).
3. Regenerate:

   ```bash
   ./scripts/generate-api-docs.sh
   ```

4. Commit the regenerated `docs/proto/rbs_rest_api.yaml`,
   `docs/api/rbs/md/rbs_rest_api.md`, and `docs/api/rbs/html/rbs_rest_api.html`.

> `test_all.sh` checks OpenAPI **YAML** drift only. In CI (`CI=true`),
> `./scripts/generate-api-docs.sh` also verifies Markdown/HTML under
> `docs/api/rbs/`; updating YAML alone can still fail the pipeline.

#### RBC SDK / `rbc-cli` (`rbc`)

- For behavior, configuration, or `rbc-cli` flag changes, update
  [`docs/usage_guide/rbc.md`](docs/usage_guide/rbc.md).
- For public SDK type or FFI surface changes, run `python3 scripts/gen-rbc-sdk-docs.py`
  and commit the updated `docs/api/rbc/sdk.md`.

#### `rbs-cli` / admin client (`tools`)

- For command, subcommand, flag, or environment variable changes, update
  [`docs/usage_guide/rbs_cli.md`](docs/usage_guide/rbs_cli.md).

#### Project & maintainer docs

Update the relevant documentation and keep it aligned with code, `scripts/`, and
generated artifacts:

| Change type | Where to update |
|-------------|-----------------|
| AI/contributor quick reference, workspace layout, naming, security invariant summary | [`AGENTS.md`](AGENTS.md) (keep it short; put procedures in this file and `docs/` — do not duplicate long guides) |
| Architecture, component boundaries, runtime flows, threat model | [`docs/design/architecture.md`](docs/design/architecture.md) (security content must match `AGENTS.md` § Security Invariants) |
| Local build, install, container, RPM | [`docs/build/build_and_install.md`](docs/build/build_and_install.md), [`docs/build/rpm.md`](docs/build/rpm.md) |
| Repository entry point and quick links | [`README.md`](README.md) |
| Merge gate, e2e suites, fixture conventions | [`tests/README.md`](tests/README.md), [`tests/e2e/rbs/README.md`](tests/e2e/rbs/README.md), etc. |
| This contribution workflow | [`CONTRIBUTING.md`](CONTRIBUTING.md) (**keep Chinese and English in sync**) |

The maintainer documents listed above, except this file, must be written in
**English**. For documentation-only MRs, state in the MR description that you
checked the documented commands, paths, and dependencies against the repository.

### 7. Run the Merge Gate

**Merge gate** (required before submission): `./tests/test_all.sh` runs Cargo
workspace tests, an OpenAPI **YAML** drift check, and then pytest e2e. It does
**not** run `cargo clippy` or `cargo deny check`.

```bash
# Default: Cargo workspace tests + OpenAPI YAML drift + pytest e2e
./tests/test_all.sh
```

**API changes (`rbs`):** In addition to the merge gate, run
`./scripts/generate-api-docs.sh` per §6 and commit the YAML, Markdown, and HTML
artifacts.

**SDK / CLI changes (`rbc`, `tools`):** Update usage guides and (when applicable)
`docs/api/rbc/sdk.md` per §6; run `./tests/test_all.sh --suite rbc` or
`--suite tools` (or the corresponding `cargo test -p …`).

**Docs-only changes:** Use a `docs/` branch prefix; commit messages such as
`docs(architecture):`, `docs(build):`, or `docs(agents):`. No new tests are
required when Rust, scripts, and generated artifacts are untouched. State in the
MR that you verified the documented commands and paths. If code changes land in
the same MR, the full merge gate still applies.

**Quality gates** (§4; run them locally before merge; the pipeline may enforce
additional checks):

```bash
cargo fmt
cargo clippy-all    # or cargo clippy
cargo deny-all      # or cargo deny check
```

Fast Rust-only iteration:

```bash
cargo test --workspace
cargo test -p rbs-core
cargo test -p rbs-rest
cargo test -p rbc
cargo test -p rbs-cli
```

E2E only, or a narrower merge gate (see [`tests/README.md`](tests/README.md) and
[`AGENTS.md`](AGENTS.md) Testing):

```bash
./tests/run_e2e.sh --suite rbs
./tests/run_e2e.sh --suite rbc
./tests/run_e2e.sh --suite tools
ENABLE_E2E_TESTS=0 ./tests/test_all.sh      # skip e2e
./tests/test_all.sh --suite rbs               # RBS Cargo packages + rbs e2e
./tests/test_all.sh --suite rbc               # rbc Cargo + rbc e2e
./tests/test_all.sh --suite tools             # tools Cargo + tools e2e
```

**Requirement:** The merge gate (`./tests/test_all.sh`) must pass before merging.

### 8. Commit Your Changes

Write clear, concise, descriptive commit messages using
[Conventional Commits](https://www.conventionalcommits.org/) style with a
scope. Match the existing history (for example, `fix(rbs):`, `feat(rbc):`,
`fix(tools):`, `docs(architecture):`, `docs(build):`, `docs(agents):`,
`docs(tests):`, `test(tools):`).

After a GitCode Merge Request is merged, the commit history may show an `!NN`
prefix (for example `!54`) or `See merge request: …!NN`; the platform adds this
automatically. Do not put `!NN` in branch names or commit messages yourself.

Example:

```bash
git add .
git commit -m "fix(rbs): handle null provider in ResourceService (fixes #42)"
```

### 9. Push Your Changes

Push your new branch to your fork:

```bash
git push origin feature/your-feature-name
```

### 10. Create a Merge Request (MR)

Open a merge request from your forked branch to the main repository's target
branch (usually `master`).

**Detailed Description:** Include a complete description of your changes, the
rationale behind them, and any relevant issue numbers (for example, Closes #101).
Call out any change that affects the security invariants in
[`AGENTS.md` § Security Invariants](AGENTS.md#security-invariants).

**Checklist:** Consider including this short checklist in your MR description:

Merge gate:

- [ ] `./tests/test_all.sh` passes
- [ ] API changes (`rbs`): `generate-api-docs.sh` was run per §6, and all artifacts are committed
- [ ] SDK / CLI changes (`rbc`, `tools`): usage guides are updated per §6, and `docs/api/rbc/sdk.md` is updated when applicable

Quality gates (§4):

- [ ] `cargo fmt` was run
- [ ] `cargo clippy` passes
- [ ] `cargo deny check` passes

Other:

- [ ] Tests added / updated
- [ ] Maintainer / architecture / build docs (`AGENTS.md`, `docs/design/`, `docs/build/`, `README.md`, etc.) are updated per §6 and aligned with code/scripts
- [ ] No secrets / keys committed

### 11. Before Merge

- Ensure all CI checks pass (`./tests/test_all.sh` locally, §4 quality gates, plus
  pipeline checks).
- Ensure the Merge Request has been reviewed by at least two project maintainers.
- Address all review comments. If comments conflict, schedule a
  meeting and coordinate among all reviewers to reach a consensus.
- Only then request maintainers to merge the Merge Request.

### Language

This document is written in both Chinese and English. Both versions are equally
effective. If the two versions conflict or diverge, the English version prevails.
