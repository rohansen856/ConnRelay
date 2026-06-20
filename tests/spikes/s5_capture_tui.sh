#!/usr/bin/env bash
# Spike S5 capture: record a TUI's raw output stream inside tmux, resize it
# midway, and save tmux's final screen as ground truth for the xterm.dart
# replay test (apps/mobile_spike/app/test/xterm_tui_test.dart).
#
#   tests/spikes/s5_capture_tui.sh <name> <command...>
#
# Output goes to apps/mobile_spike/app/test/fixtures/ (gitignored: captures
# can contain account names or paths). The program runs in an empty temporary
# directory. Optional KEYS (tmux key names, space-separated) are sent after
# PRE seconds to get past first-run dialogs; no prompt text is ever sent. The
# program is stopped with Ctrl-C.
set -euo pipefail
name=$1; shift
root=$(cd "$(dirname "$0")/../.." && pwd)
out="$root/apps/mobile_spike/app/test/fixtures"
mkdir -p "$out"
work=$(mktemp -d /tmp/prw-s5.XXXXXX)
sock="$work/t.sock"
tm() { tmux -f /dev/null -S "$sock" "$@"; }
trap 'tm kill-server 2>/dev/null || true; rm -rf "$work"' EXIT

raw="$out/$name.raw"; : > "$raw"
cmd=$(printf '%q ' "$@")
tm new-session -d -s s5 -x 100 -y 30 -c "$work" "sleep 1; TERM=xterm-256color exec $cmd"
tm set-option -t s5 status off
tm pipe-pane -t s5 -O "cat >> '$raw'"
if [[ -n ${KEYS:-} ]]; then
  sleep "${PRE:-4}"
  for k in $KEYS; do tm send-keys -t s5 "$k"; sleep 0.7; done
fi
sleep "${PHASE1:-6}"
tm capture-pane -t s5 -p > "$out/$name.before.screen"
wc -c < "$raw" | tr -d ' ' > "$out/$name.resize_at"
tm resize-window -t s5 -x 80 -y 24
sleep "${PHASE2:-4}"
tm capture-pane -t s5 -p > "$out/$name.screen"
wc -c < "$raw" | tr -d ' ' > "$out/$name.end_at"
tm send-keys -t s5 C-c 2>/dev/null || true; sleep 0.5; tm send-keys -t s5 C-c 2>/dev/null || true; sleep 0.5
echo "$name: $(wc -c < "$raw") bytes, resize at $(cat "$out/$name.resize_at")"
