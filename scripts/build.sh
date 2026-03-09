#!/bin/bash
# General build script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

echo "Building globaltrustauthority-rbs project..."

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo "Error: cargo is not installed. Please install Rust first."
    exit 1
fi

# Build all projects
cargo build --release

echo "Build completed successfully!"
echo "Binaries are located in: $PROJECT_ROOT/target/release/"
