#!/usr/bin/env bash
# Install prw-agent for the current user (no root needed).
#   ./install.sh path/to/prw-agent
set -euo pipefail
bin=${1:?usage: install.sh path/to/prw-agent}
[[ $EUID -ne 0 ]] || { echo "run as your normal user, not root"; exit 1; }
command -v tmux >/dev/null || echo "warning: tmux is not installed; terminals will be disabled"
install -Dm755 "$bin" "$HOME/.local/bin/prw-agent"
install -Dm644 "$(dirname "$0")/prw-agent.service" "$HOME/.config/systemd/user/prw-agent.service"
systemctl --user daemon-reload
echo "Installed. Next:"
echo "  prw-agent pair --server https://api.example.invalid"
echo "  systemctl --user enable --now prw-agent"
echo "  loginctl enable-linger \"$USER\"   # optional: keep running while logged out"
