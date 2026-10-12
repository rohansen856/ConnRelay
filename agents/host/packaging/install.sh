#!/usr/bin/env bash
# Install connrelay-agent for the current user (no root needed).
#   ./install.sh path/to/connrelay-agent
set -euo pipefail
bin=${1:?usage: install.sh path/to/connrelay-agent}
[[ $EUID -ne 0 ]] || { echo "run as your normal user, not root"; exit 1; }
command -v tmux >/dev/null || echo "warning: tmux is not installed; terminals will be disabled"
install -Dm755 "$bin" "$HOME/.local/bin/connrelay-agent"
install -Dm644 "$(dirname "$0")/connrelay-agent.service" "$HOME/.config/systemd/user/connrelay-agent.service"
systemctl --user daemon-reload
echo "Installed. Next:"
echo "  connrelay-agent pair --server https://api.example.invalid"
echo "  systemctl --user enable --now connrelay-agent"
echo "  loginctl enable-linger \"$USER\"   # optional: keep running while logged out"
