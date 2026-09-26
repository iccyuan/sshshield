#!/usr/bin/env bash
# SSHShield one-click installer.
#   Local:  sudo ./install.sh              (uses sshshield-linux-<arch> next to this script)
#   Remote: curl -fsSL https://raw.githubusercontent.com/iccyuan/sshshield/main/install.sh | sudo bash
#   Remove: sudo ./install.sh uninstall [--purge]
set -euo pipefail

REPO="${SSHSHIELD_REPO:-iccyuan/sshshield}"
VERSION="${SSHSHIELD_VERSION:-latest}"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
blue()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { red "请用 root 运行: sudo $0"; exit 1; }
[ "$(uname -s)" = "Linux" ] || { red "仅支持 Linux"; exit 1; }

if [ "${1:-}" = "uninstall" ]; then
  shift
  exec /usr/local/bin/sshshield uninstall "$@"
fi

case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) red "不支持的架构: $(uname -m)"; exit 1 ;;
esac

DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo .)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
BIN="$TMP/sshshield"

if [ -f "$DIR/sshshield-linux-$ARCH" ]; then
  blue "使用本地二进制 $DIR/sshshield-linux-$ARCH"
  cp "$DIR/sshshield-linux-$ARCH" "$BIN"
elif [ -f "$DIR/sshshield" ] && [ "$DIR" != "/usr/local/bin" ]; then
  blue "使用本地二进制 $DIR/sshshield"
  cp "$DIR/sshshield" "$BIN"
else
  if [ "$VERSION" = "latest" ]; then
    URL="https://github.com/$REPO/releases/latest/download/sshshield-linux-$ARCH"
  else
    URL="https://github.com/$REPO/releases/download/$VERSION/sshshield-linux-$ARCH"
  fi
  URL="${SSHSHIELD_URL:-$URL}"
  blue "下载 $URL"
  if command -v curl >/dev/null; then
    curl -fL --retry 3 -o "$BIN" "$URL"
  elif command -v wget >/dev/null; then
    wget -qO "$BIN" "$URL"
  else
    red "需要 curl 或 wget"; exit 1
  fi
fi

chmod +x "$BIN"
"$BIN" version >/dev/null || { red "二进制无法运行（架构不匹配？）"; exit 1; }
"$BIN" install "$@"
