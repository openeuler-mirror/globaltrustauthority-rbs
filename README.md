# globaltrustauthority-rbs

**Resource Broker Service (RBS)** securely releases keys, certificates, and other sensitive resources to workloads that pass remote attestation through the [Global Trust Authority](https://gitcode.com/openeuler/global-trust-authority).

## Overview

This repository is a **Rust workspace** for policy-driven trusted resource delivery. It combines remote attestation, access policy evaluation, protected resource retrieval, operator tooling, and deployable service packaging for confidential computing and zero-trust environments.

It includes:

- **`rbs`** — Broker service that verifies workload trust, evaluates access policies, and releases protected resources only to authorized attested clients.
- **`rbc`** — Client SDK and optional command-line client that helps applications submit attestation evidence, manage sessions, and retrieve keys, certificates, or other protected resources from RBS.
- **`rbs-cli`** — Operator tool for managing broker users, policies, resources, certificates, tokens, and client-side verification workflows from scripts or an interactive shell.

## Quick start

For a step-by-step setup, build, test, run, and service verification, see [**Quick start**](docs/build/build_and_install.md#2-quick-start) in`docs/build/build_and_install.md`.

## Documentation

| Topic | Location |
|-------|----------|
| Build, run, test | [build_and_install.md](docs/build/build_and_install.md) |
| RPM installation | [rpm.md](docs/build/rpm.md) |
| Container deployment | [docker/](deployment/docker/) |
| REST API | [YAML](docs/proto/rbs_rest_api.yaml) · [MD](docs/api/rbs/md/rbs_rest_api.md) · [HTML](docs/api/rbs/html/rbs_rest_api.html) |
| Test suite | [README.md](tests/README.md) |
| Sample config | [rbs.yaml](rbs/conf/rbs.yaml) |
| Developer tooling | [Further reading](docs/build/build_and_install.md#7-further-reading-and-tooling) |

## License

Licensed under the **Mulan Public License, version 2** — see [LICENSE](LICENSE).
