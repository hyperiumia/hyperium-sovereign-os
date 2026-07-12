#!/bin/bash
set -e

echo "========================================="
echo "  Building Sovereign Agent"
echo "========================================="

cd "$(dirname "$0")"

echo ""
echo "[1/3] Compiling release binary..."
cargo build --release 2>&1

echo ""
echo "[2/3] Binary location:"
ls -lh target/release/sovereign-agent

echo ""
echo "[3/3] Installation instructions:"
echo ""
echo "  # Copy binary"
echo "  sudo cp target/release/sovereign-agent /usr/local/bin/"
echo ""
echo "  # Copy config"
echo "  sudo mkdir -p /etc/sovereign-agent"
echo "  sudo cp config/agent.toml /etc/sovereign-agent/"
echo ""
echo "  # Install systemd service"
echo "  sudo cp systemd/sovereign-agent.service /etc/systemd/system/"
echo "  sudo systemctl daemon-reload"
echo "  sudo systemctl enable sovereign-agent"
echo "  sudo systemctl start sovereign-agent"
echo ""
echo "  # Check status"
echo "  sudo systemctl status sovereign-agent"
echo "  sudo journalctl -u sovereign-agent -f"
echo ""
echo "========================================="
echo "  Build complete"
echo "========================================="
