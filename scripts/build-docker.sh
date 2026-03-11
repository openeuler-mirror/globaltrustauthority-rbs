#!/bin/bash
# Docker image build script (only builds RBS service)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

VERSION=${VERSION:-latest}
REGISTRY=${REGISTRY:-gta-rbs}

echo "Building RBS Docker image for version $VERSION..."

# Only build RBS image (RBC and tools do not need containerization)
echo "Building RBS Docker image..."
docker build -f deployment/docker/dockerfile -t "$REGISTRY/rbs:$VERSION" .

echo "Docker image built successfully!"
echo "Image: $REGISTRY/rbs:$VERSION"
echo ""
echo "Note: RBC and tools are not containerized, use RPM deployment instead."
