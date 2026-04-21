#!/usr/bin/env bash
# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
#
# Build-related dependency detection and optional distro package installs.
# Auto-install is off by default; set ENABLE_AUTO_INSTALL_DEPS=1 to allow installs on
# supported distros (still blocked when CI=true or DISABLE_AUTO_INSTALL_DEPS=1).
# Source after setting SCRIPT_DIR to the scripts/ directory:
#   SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#   # shellcheck source=lib/build-deps.sh
#   source "$SCRIPT_DIR/lib/build-deps.sh"

# Directory containing this file (scripts/lib/), used only to source sibling helpers.
_build_deps_lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/os-pkg.sh
source "$_build_deps_lib_dir/os-pkg.sh"

# After a distro package install, assert every named command exists on PATH.
_assert_commands_on_path() {
    local missing=()
    local c
    for c in "$@"; do
        if ! command -v "$c" >/dev/null 2>&1; then
            missing+=("$c")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "error: after package install, still missing on PATH: ${missing[*]}" >&2
        return 1
    fi
    return 0
}

# Rust cargo (workspace build). Uses distro packages; for latest toolchains use rustup instead.
ensure_cargo() {
    if command -v cargo >/dev/null 2>&1; then
        return 0
    fi
    if build_deps_auto_install_disabled; then
        echo "error: cargo is not installed. Install Rust (https://rustup.rs) or distro packages, or set ENABLE_AUTO_INSTALL_DEPS=1 to attempt a supported distro install." >&2
        exit 1
    fi

    local family
    family="$(detect_pkg_family)"
    echo "notice: cargo not found; attempting install (pkg_family=${family}) ..." >&2

    case "$family" in
        apt)
            if ! command -v apt-get >/dev/null 2>&1; then
                echo "error: apt-get not found; install cargo manually." >&2
                exit 1
            fi
            run_privileged apt-get update -qq
            run_privileged env DEBIAN_FRONTEND=noninteractive apt-get install -y cargo ||
                run_privileged env DEBIAN_FRONTEND=noninteractive apt-get install -y rustc cargo
            ;;
        dnf)
            if command -v dnf >/dev/null 2>&1; then
                run_privileged dnf install -y cargo rust || run_privileged dnf install -y cargo
            elif command -v yum >/dev/null 2>&1; then
                run_privileged yum install -y cargo rust || run_privileged yum install -y cargo
            else
                echo "error: neither dnf nor yum found; install cargo manually." >&2
                exit 1
            fi
            ;;
        *)
            echo "error: unsupported distro for automatic cargo install (pkg_family=${family})." >&2
            echo "Install Rust via https://rustup.rs or your distribution packages." >&2
            exit 1
            ;;
    esac

    _assert_commands_on_path cargo || exit 1
    echo "notice: distro-installed cargo may be older than this workspace needs; if cargo build fails on Cargo.lock or edition, use https://rustup.rs/ and verify cargo --version." >&2
}

# RPM packaging: cargo, rpmbuild, and a C toolchain (matches rpm/*.spec %build using cargo).
ensure_rpm_build_tools() {
    ensure_cargo

    local need=()
    local c
    for c in rpmbuild gcc g++ make; do
        command -v "$c" >/dev/null 2>&1 || need+=("$c")
    done
    [[ ${#need[@]} -eq 0 ]] && return 0

    if build_deps_auto_install_disabled; then
        echo "error: missing build tools: ${need[*]}. Install rpm-build / gcc / make for your OS, or set ENABLE_AUTO_INSTALL_DEPS=1 to attempt a supported distro install." >&2
        exit 1
    fi

    local family
    family="$(detect_pkg_family)"
    echo "notice: installing RPM build dependencies (pkg_family=${family}) ..." >&2

    case "$family" in
        apt)
            if ! command -v apt-get >/dev/null 2>&1; then
                echo "error: apt-get not found." >&2
                exit 1
            fi
            run_privileged apt-get update -qq
            # Debian/Ubuntu: 'rpm' provides rpmbuild; build-essential pulls gcc/g++/make.
            run_privileged env DEBIAN_FRONTEND=noninteractive apt-get install -y rpm build-essential
            ;;
        dnf)
            if command -v dnf >/dev/null 2>&1; then
                run_privileged dnf install -y rpm-build rpmdevtools gcc gcc-c++ make
            elif command -v yum >/dev/null 2>&1; then
                run_privileged yum install -y rpm-build rpmdevtools gcc gcc-c++ make
            else
                echo "error: neither dnf nor yum found." >&2
                exit 1
            fi
            ;;
        *)
            echo "error: unsupported distro for automatic RPM tooling (pkg_family=${family})." >&2
            echo "On openEuler-style systems: dnf install -y rpm-build rpmdevtools gcc gcc-c++ make" >&2
            exit 1
            ;;
    esac

    _assert_commands_on_path rpmbuild gcc g++ make || exit 1
}

# Docker CLI for image builds (daemon must be running separately); build-docker.sh uses buildx when engine=docker.
ensure_docker_cli() {
    if command -v docker >/dev/null 2>&1; then
        return 0
    fi
    if build_deps_auto_install_disabled; then
        echo "error: docker is not installed. Install Docker Engine / CLI for your OS, or set ENABLE_AUTO_INSTALL_DEPS=1 to attempt a supported distro install." >&2
        exit 1
    fi

    local family
    family="$(detect_pkg_family)"
    echo "notice: docker not found; attempting install (pkg_family=${family}) ..." >&2

    case "$family" in
        apt)
            if ! command -v apt-get >/dev/null 2>&1; then
                echo "error: apt-get not found; install Docker manually." >&2
                exit 1
            fi
            run_privileged apt-get update -qq
            run_privileged env DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io
            ;;
        dnf)
            if command -v dnf >/dev/null 2>&1; then
                run_privileged dnf install -y docker ||
                    run_privileged dnf install -y moby-engine ||
                    run_privileged dnf install -y podman-docker
            elif command -v yum >/dev/null 2>&1; then
                run_privileged yum install -y docker ||
                    run_privileged yum install -y podman-docker
            else
                echo "error: neither dnf nor yum found; install docker manually." >&2
                exit 1
            fi
            ;;
        *)
            echo "error: unsupported distro for automatic docker install (pkg_family=${family})." >&2
            exit 1
            ;;
    esac

    if ! command -v docker >/dev/null 2>&1; then
        echo "error: docker CLI still not on PATH after package install." >&2
        exit 1
    fi
    echo "notice: ensure the Docker daemon is running and your user can access it (e.g. docker group)." >&2
}
