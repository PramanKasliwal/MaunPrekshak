#!/usr/bin/env bash
set -e

REPO="PramanKasliwal/maunprekshak"
INSTALL_DIR="${HOME}/.local/bin"

echo "📡 Downloading latest MaunPrekshak for Linux..."
mkdir -p "${INSTALL_DIR}"

# Find the download URL of the latest compiled binary from GitHub Releases
DOWNLOAD_URL=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep "browser_download_url.*mp-linux-x86_64" \
  | cut -d : -f 2,3 \
  | tr -d '\" ')

if [ -z "$DOWNLOAD_URL" ]; then
  echo "❌ Error: Could not find pre-built binary for the latest release."
  echo "Please check https://github.com/${REPO}/releases"
  exit 1
fi

curl -sSL "$DOWNLOAD_URL" -o "${INSTALL_DIR}/mp"
chmod +x "${INSTALL_DIR}/mp"

echo ""
echo "✅ MaunPrekshak installed successfully to: ${INSTALL_DIR}/mp"
echo ""

# Check if ~/.local/bin is in PATH
if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
  echo "⚠️ Notice: ${INSTALL_DIR} is not in your PATH."
  echo "Add this to your ~/.bashrc or ~/.zshrc:"
  echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
  echo ""
fi

echo "Run 'mp --help' to get started!"
