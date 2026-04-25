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
# RPM build script.
#
# Optional auto-install: cargo, rpmbuild, gcc/g++, make (apt or dnf/yum) when missing.
# Off by default; set ENABLE_AUTO_INSTALL_DEPS=1 to allow. CI=true or DISABLE_AUTO_INSTALL_DEPS=1 forbids.
#
# Prefer: scripts/build.sh rpm

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
    cat <<'EOF'
Usage: scripts/build-rpm.sh
   or: scripts/build.sh rpm

Builds RBS / RBC / RBS-CLI RPM packages from the workspace.

Environment:
  VERSION        Package version (default: 0.1.0)
  RELEASE        RPM release (default: 1)
  RPM_BUILD_DIR  rpmbuild topdir (default: <repo>/rpm-build). Use an absolute path in CI or
                 when you must avoid writing under the repository tree.

Example:
  VERSION=1.0.0 RELEASE=2 scripts/build-rpm.sh
  RPM_BUILD_DIR=/tmp/rbs-rpmbuild scripts/build-rpm.sh
EOF
}

if [[ "${1:-}" == "-h" ]] || [[ "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

# shellcheck source=lib/build-deps.sh
source "$SCRIPT_DIR/lib/build-deps.sh"

cd "$PROJECT_ROOT"

ensure_rpm_build_tools

VERSION=${VERSION:-0.1.0}
RELEASE=${RELEASE:-1}

echo "Building RPM packages for version $VERSION-$RELEASE..."

# rpmbuild topdir: default under repo; override with RPM_BUILD_DIR (absolute or repo-relative).
if [[ -n "${RPM_BUILD_DIR:-}" ]]; then
    if [[ "${RPM_BUILD_DIR}" == /* ]]; then
        RPMBUILD_TOPDIR="$RPM_BUILD_DIR"
    else
        RPMBUILD_TOPDIR="$PROJECT_ROOT/$RPM_BUILD_DIR"
    fi
else
    RPMBUILD_TOPDIR="$PROJECT_ROOT/rpm-build"
fi

# Safety: refuse obviously unsafe rpmbuild topdirs (this script wipes RPMBUILD_TOPDIR before use).
case "$RPMBUILD_TOPDIR" in
    / | /bin | /boot | /dev | /etc | /lib | /lib64 | /proc | /sys | /usr | /var | "$HOME" | "$HOME"/)
        echo "error: refusing RPM_BUILD_DIR/RPMBUILD_TOPDIR=$RPMBUILD_TOPDIR (too dangerous to clean and reuse)." >&2
        exit 1
        ;;
esac

# Create build directory
rm -rf "$RPMBUILD_TOPDIR"
mkdir -p "$RPMBUILD_TOPDIR"

# Build Rust project
echo "Building Rust binaries..."
cargo build --release

# Build RBS RPM
echo "Building RBS RPM..."
cd "$PROJECT_ROOT"
rpmbuild -bb rpm/rbs.spec \
    --define "_topdir $RPMBUILD_TOPDIR" \
    --define "_project_root $PROJECT_ROOT" \
    --define "version $VERSION" \
    --define "release $RELEASE" \
    --buildroot "$RPMBUILD_TOPDIR/BUILDROOT"

# Build RBC RPM
echo "Building RBC RPM..."
rpmbuild -bb rpm/rbc.spec \
    --define "_topdir $RPMBUILD_TOPDIR" \
    --define "_project_root $PROJECT_ROOT" \
    --define "version $VERSION" \
    --define "release $RELEASE" \
    --buildroot "$RPMBUILD_TOPDIR/BUILDROOT"

# Build RBS-CLI RPM
echo "Building RBS-CLI RPM..."
rpmbuild -bb rpm/rbs-cli.spec \
    --define "_topdir $RPMBUILD_TOPDIR" \
    --define "_project_root $PROJECT_ROOT" \
    --define "version $VERSION" \
    --define "release $RELEASE" \
    --buildroot "$RPMBUILD_TOPDIR/BUILDROOT"

echo "RPM packages built successfully!"
echo "RPM files are located in: $RPMBUILD_TOPDIR/RPMS/$(rpm --eval %_arch)/"
