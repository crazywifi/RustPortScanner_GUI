#!/usr/bin/env bash
# PortScanner v2.0 — Linux build script
set -e

echo "========================================"
echo "  PortScanner v2.0 — Linux Build"
echo "========================================"

# Check for Rust
if ! command -v cargo &>/dev/null; then
  echo "[!] Rust not found. Installing via rustup..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
  source "$HOME/.cargo/env"
fi

# Check for libpcap (required by pnet for SYN scan)
if ! dpkg -l libpcap-dev &>/dev/null 2>&1 && ! rpm -q libpcap-devel &>/dev/null 2>&1; then
  echo "[*] Attempting to install libpcap-dev (required for SYN scan mode)..."
  if command -v apt-get &>/dev/null; then
    sudo apt-get install -y libpcap-dev
  elif command -v yum &>/dev/null; then
    sudo yum install -y libpcap-devel
  elif command -v dnf &>/dev/null; then
    sudo dnf install -y libpcap-devel
  else
    echo "[!] Could not install libpcap automatically."
    echo "    Install it manually: apt-get install libpcap-dev"
    echo "    SYN scan will fall back to TCP Connect without it."
  fi
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
  echo "  $BINARY --gui               # Launch web GUI"
  echo "  $BINARY 192.168.1.1         # Quick scan"
  echo "  $BINARY --help              # Show all options"
  echo ""
  echo "NOTE: SYN/UDP scan modes require root:"
  echo "  sudo $BINARY 192.168.1.1 --syn -p 1-1024"
else
  echo "[!] Build failed. Check output above."
  exit 1
fi
