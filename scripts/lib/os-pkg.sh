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
# Shared helpers for detecting distro package family and optional non-interactive installs.
# Intended to be sourced from scripts under scripts/*.sh (not executed directly).

# Run a command as root, or via sudo when the caller is not uid 0.
# Caller must check exit status (or rely on set -e); failure means no root/sudo.
run_privileged() {
    if [[ "$(id -u)" -eq 0 ]]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        echo "error: need root or sudo to install OS packages." >&2
        return 1
    fi
}

# Returns: apt | dnf | none
detect_pkg_family() {
    if [[ ! -f /etc/os-release ]]; then
        echo none
        return
    fi
    # shellcheck source=/dev/null
    . /etc/os-release
    local id_lc like_lc
    id_lc="$(echo "${ID:-unknown}" | tr '[:upper:]' '[:lower:]')"
    like_lc="$(echo "${ID_LIKE:-}" | tr '[:upper:]' '[:lower:]')"

    case "$id_lc" in
        ubuntu | debian | linuxmint | pop | elementary | zorin) echo apt ;;
        raspbian) echo apt ;;
        openeuler) echo dnf ;;
        *)
            if [[ "$like_lc" == *debian* ]] || [[ "$like_lc" == *ubuntu* ]]; then
                echo apt
            elif [[ "$like_lc" == *rhel* ]] || [[ "$like_lc" == *fedora* ]] ||
                [[ "$like_lc" == *centos* ]] || [[ "$like_lc" == *openeuler* ]]; then
                echo dnf
            else
                echo none
            fi
            ;;
    esac
}

# True when automatic OS package install must not run.
# Default is off (no sudo/distro installs). Set ENABLE_AUTO_INSTALL_DEPS=1 on supported distros
# to allow sourced helpers to install missing packages. CI=true or DISABLE_AUTO_INSTALL_DEPS=1
# always forbids auto-install (even if ENABLE_AUTO_INSTALL_DEPS is set).
build_deps_auto_install_disabled() {
    if [[ "${CI:-}" == "true" ]]; then
        return 0
    fi
    if [[ "${DISABLE_AUTO_INSTALL_DEPS:-}" == "1" ]]; then
        return 0
    fi
    if [[ "${ENABLE_AUTO_INSTALL_DEPS:-}" == "1" ]]; then
        return 1
    fi
    return 0
}
