#!/usr/bin/env bash
# Cross-compile Linux binaries and a release tarball into dist/.
set -euo pipefail
cd "$(dirname "$0")"

VERSION="${1:-$(git describe --tags --always 2>/dev/null || echo dev)}"
rm -rf dist && mkdir -p dist/sshshield

for arch in amd64 arm64; do
  echo "build linux/$arch"
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath \
    -ldflags "-s -w -X main.version=$VERSION" \
    -o "dist/sshshield-linux-$arch" .
  cp "dist/sshshield-linux-$arch" dist/sshshield/
done

cp install.sh README.md dist/sshshield/
tar -C dist -czf "dist/sshshield-$VERSION.tar.gz" sshshield
rm -rf dist/sshshield
ls -lh dist
