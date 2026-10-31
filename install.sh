#!/bin/sh
# Hedwig installer for Linux and macOS.
# Usage: curl -fsSL https://github.com/D3C0Y-1-0/BubblySorted_D3C0Y_YashSingh/releases/latest/download/install.sh | sh
set -eu

REPO="D3C0Y-1-0/BubblySorted_D3C0Y_YashSingh"

if ! command -v uv >/dev/null 2>&1; then
  echo "Installing uv..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
  PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
  export PATH
fi

echo "Finding the latest Hedwig release..."
WHEEL_URL=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
  | grep -o '"browser_download_url": *"[^"]*\.whl"' \
  | head -n 1 \
  | sed 's/.*"\(https[^"]*\)"/\1/')

if [ -z "$WHEEL_URL" ]; then
  echo "Could not find a Hedwig wheel in the latest release." >&2
  exit 1
fi

echo "Installing $WHEEL_URL"
uv tool install --force --python 3.12 "hedwig @ $WHEEL_URL"
uv tool update-shell >/dev/null 2>&1 || true

echo
echo "Hedwig installed. Open a new terminal and run: hedwig config"
