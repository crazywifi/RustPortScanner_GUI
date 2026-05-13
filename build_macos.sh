#!/usr/bin/env bash
# PortScanner v2.0 — macOS build script
set -e

echo "========================================"
echo "  PortScanner v2.0 — macOS Build"
echo "========================================"

# Check for Rust
if ! command -v cargo &>/dev/null; then
  echo "[!] Rust not found. Installing via rustup..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
  source "$HOME/.cargo/env"
fi

# Check for libpcap (usually pre-installed on macOS via XCode tools)
if ! xcode-select -p &>/dev/null; then
  echo "[*] Installing Xcode Command Line Tools (required for libpcap)..."
  xcode-select --install
fi

echo ""
echo "[*] Building release binary..."
cargo build --release

BINARY="./target/release/portscanner"

if [ -f "$BINARY" ]; then
  echo ""
  echo "[✓] Build successful!"
  echo ""
  echo "  Binary : $BINARY"
  echo "  Size   : $(du -sh $BINARY | cut -f1)"
  echo ""
  echo "Usage:"
  echo "  $BINARY --gui               # Launch web GUI (opens browser)"
  echo "  $BINARY 192.168.1.1         # Quick scan"
  echo "  $BINARY --help              # Show all options"
  echo ""
  echo "NOTE: SYN/UDP modes require root on macOS:"
  echo "  sudo $BINARY 192.168.1.1 --syn"
else
  echo "[!] Build failed. Check output above."
  exit 1
fi
