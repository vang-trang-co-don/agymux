#!/bin/sh
set -eu

# agymux Installer for vang-trang-co-don/agymux
# Installs agymux to ~/.local/bin/agymux

REPO="vang-trang-co-don/agymux"
CMD="agymux"
BIN_DIR="${AGYMUX_BIN_DIR:-$HOME/.local/bin}"

# Detect OS
OS="$(uname -s)"
case "$OS" in
  Linux*)  PLATFORM_OS="linux" ;;
  Darwin*) PLATFORM_OS="darwin" ;;
  MINGW*|MSYS*|CYGWIN*) PLATFORM_OS="windows" ;;
  *)
    printf "Error: Unsupported operating system: %s\n" "$OS" >&2
    exit 1
    ;;
esac

# Detect Architecture
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) PLATFORM_ARCH="amd64" ;;
  arm64|aarch64) PLATFORM_ARCH="arm64" ;;
  *)
    printf "Error: Unsupported architecture: %s\n" "$ARCH" >&2
    exit 1
    ;;
esac

PLATFORM="${PLATFORM_OS}-${PLATFORM_ARCH}"
printf "\033[1;36m==>\033[0m Detected platform: \033[1m%s\033[0m\n" "$PLATFORM"

mkdir -p "$BIN_DIR"
TARGET_EXE="$BIN_DIR/$CMD"
if [ "$PLATFORM_OS" = "windows" ]; then
  TARGET_EXE="$BIN_DIR/${CMD}.exe"
fi

# 1. Check if running from local source tree
if [ -f "./cmd/agymux/main.go" ] && command -v go >/dev/null 2>&1; then
  printf "\033[1;36m==>\033[0m Building from local workspace...\n"
  go build -o "$TARGET_EXE" ./cmd/agymux
  chmod +x "$TARGET_EXE"
  printf "\n\033[1;32m✓ agymux installed successfully to %s\033[0m\n" "$TARGET_EXE"
  exit 0
fi

# 2. Try downloading pre-compiled binary from GitHub Releases
if [ "$PLATFORM_OS" = "windows" ]; then
  ARCHIVE_NAME="agymux-${PLATFORM}.zip"
else
  ARCHIVE_NAME="agymux-${PLATFORM}.tar.gz"
fi

DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${ARCHIVE_NAME}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

DOWNLOADED=0
if command -v curl >/dev/null 2>&1; then
  if curl -fL --progress-bar -o "$TMP_DIR/$ARCHIVE_NAME" "$DOWNLOAD_URL" 2>/dev/null; then
    DOWNLOADED=1
  fi
elif command -v wget >/dev/null 2>&1; then
  if wget -q --show-progress -O "$TMP_DIR/$ARCHIVE_NAME" "$DOWNLOAD_URL" 2>/dev/null; then
    DOWNLOADED=1
  fi
fi

if [ "$DOWNLOADED" -eq 1 ]; then
  printf "\033[1;36m==>\033[0m Extracting binary...\n"
  if [ "$PLATFORM_OS" = "windows" ]; then
    unzip -q "$TMP_DIR/$ARCHIVE_NAME" -d "$TMP_DIR"
  else
    tar -xzf "$TMP_DIR/$ARCHIVE_NAME" -C "$TMP_DIR"
  fi

  if [ -f "$TMP_DIR/$CMD" ]; then
    cp "$TMP_DIR/$CMD" "$TARGET_EXE"
  elif [ -f "$TMP_DIR/${CMD}.exe" ]; then
    cp "$TMP_DIR/${CMD}.exe" "$TARGET_EXE"
  else
    # Find any executable named agymux in subfolder
    FOUND_BIN="$(find "$TMP_DIR" -type f -name "$CMD" -o -name "${CMD}.exe" | head -n 1)"
    if [ -n "$FOUND_BIN" ]; then
      cp "$FOUND_BIN" "$TARGET_EXE"
    else
      DOWNLOADED=0
    fi
  fi
fi

# 3. Fallback: Build from source if GitHub Release asset is not available
if [ "$DOWNLOADED" -eq 0 ]; then
  printf "\033[1;33m==>\033[0m Release binary not found on GitHub. Checking build tools...\n"
  if command -v git >/dev/null 2>&1 && command -v go >/dev/null 2>&1; then
    printf "\033[1;36m==>\033[0m Building from source repository using Go...\n"
    SRC_DIR="${AGYMUX_SRC_DIR:-$HOME/.agymux/source}"
    if [ -d "$SRC_DIR/.git" ]; then
      (cd "$SRC_DIR" && git fetch origin main && git reset --hard origin/main)
    else
      git clone "https://github.com/${REPO}.git" "$SRC_DIR"
    fi
    (cd "$SRC_DIR" && go build -o "$TARGET_EXE" ./cmd/agymux)
  else
    printf "Error: Could not download release binary and build tools (git, go) are not available.\n" >&2
    printf "Please install Go 1.22+ or check https://github.com/%s/releases\n" "$REPO" >&2
    exit 1
  fi
fi

chmod +x "$TARGET_EXE"
printf "\n\033[1;32m✓ agymux installed successfully!\033[0m\n"

# Verify PATH
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    printf "\n\033[1;33mNote:\033[0m %s is not in your PATH.\n" "$BIN_DIR"
    printf "Add it to your shell configuration (e.g. ~/.bashrc or ~/.zshrc):\n\n"
    printf "  export PATH=\"%s:\$PATH\"\n\n" "$BIN_DIR"
    ;;
esac

# Check for agy binary
if ! command -v agy >/dev/null 2>&1 && [ ! -f "$HOME/.local/bin/agy" ]; then
  printf "\033[1;33mNotice:\033[0m 'agy' binary was not found in PATH or ~/.local/bin/agy.\n"
  printf "Remember to install agy (Antigravity CLI) to run queries.\n"
fi

printf "Run it with: \033[1;36m%s\033[0m\n\n" "$CMD"
