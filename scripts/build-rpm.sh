#!/bin/bash
# RPM build script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

# Check required tools
for cmd in cargo rpmbuild; do
    if ! command -v $cmd &> /dev/null; then
        echo "Error: $cmd is not installed. Please install it first."
        echo ""
        echo "Installation instructions for OpenEuler:"
        echo "  sudo yum install -y rpm-build rpmdevtools gcc gcc-c++ make"
        echo ""
        echo "For Rust toolchain:"
        echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        exit 1
    fi
done

VERSION=${VERSION:-0.1.0}
RELEASE=${RELEASE:-1}

echo "Building RPM packages for version $VERSION-$RELEASE..."

# Create build directory
BUILD_DIR="$PROJECT_ROOT/rpm-build"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Build Rust project
echo "Building Rust binaries..."
cargo build --release

# Build RBS RPM
echo "Building RBS RPM..."
cd "$PROJECT_ROOT"
rpmbuild -bb rpm/rbs.spec \
    --define "_topdir $BUILD_DIR" \
    --define "_project_root $PROJECT_ROOT" \
    --define "version $VERSION" \
    --define "release $RELEASE" \
    --buildroot "$BUILD_DIR/BUILDROOT"

# Build RBC RPM
echo "Building RBC RPM..."
rpmbuild -bb rpm/rbc.spec \
    --define "_topdir $BUILD_DIR" \
    --define "_project_root $PROJECT_ROOT" \
    --define "version $VERSION" \
    --define "release $RELEASE" \
    --buildroot "$BUILD_DIR/BUILDROOT"

# Build RBS-CLI RPM
echo "Building RBS-CLI RPM..."
rpmbuild -bb rpm/rbs-cli.spec \
    --define "_topdir $BUILD_DIR" \
    --define "_project_root $PROJECT_ROOT" \
    --define "version $VERSION" \
    --define "release $RELEASE" \
    --buildroot "$BUILD_DIR/BUILDROOT"

echo "RPM packages built successfully!"
echo "RPM files are located in: $BUILD_DIR/RPMS/$(rpm --eval %_arch)/"
