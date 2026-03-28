#!/usr/bin/env bash
# Spike S4: does a tmux session started by the agent survive an agent restart
# under `systemd --user`?
#
# The "agent" here is a transient user unit that starts a PRW tmux session the
# same way the real agent does (exec of the tmux binary on a private socket)
# and then stays running. We stop the unit and start a new one, then check the
# session and its shell PID. This runs twice:
#   KillMode=process        -> expected: session survives with the same PID
#   KillMode=control-group  -> expected: session is killed (systemd default)
set -euo pipefail

command -v systemd-run >/dev/null || { echo "SKIP: systemd-run not found"; exit 0; }
command -v tmux >/dev/null || { echo "SKIP: tmux not found"; exit 0; }
systemctl --user is-system-running >/dev/null 2>&1 || [[ $(systemctl --user is-system-running 2>/dev/null) == degraded ]] \
  || { echo "SKIP: no systemd user manager"; exit 0; }

work=$(mktemp -d /tmp/prw-s4.XXXXXX)
sock="$work/tmux.sock"
tm() { tmux -f /dev/null -S "$sock" "$@"; }
cleanup() {
  systemctl --user stop prw-s4-agent-1 prw-s4-agent-2 >/dev/null 2>&1 || true
  tm kill-server >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

agent() { # $1=unit name, $2=KillMode, $3=create|attach-only
  local script
  if [[ $3 == create ]]; then
    script="tmux -f /dev/null -S '$sock' new-session -d -s prw-s4 -x 80 -y 24 -- /bin/sh && exec sleep infinity"
  else
    script="exec sleep infinity"
  fi
  systemd-run --user --quiet --collect --unit="$1" -p KillMode="$2" /bin/sh -c "$script"
}

pane_pid() { tm list-panes -t prw-s4 -F '#{pane_pid}' 2>/dev/null || true; }
has_session() { [[ -n $(pane_pid) ]]; }

wait_for() { # $1=description, then command
  local d=$1; shift
  for _ in $(seq 1 50); do "$@" && return 0; sleep 0.1; done
  echo "timeout waiting for $d"; return 1
}

run_case() { # $1=KillMode, $2=expect survive|die
  tm kill-server >/dev/null 2>&1 || true
  agent prw-s4-agent-1 "$1" create
  wait_for "session" has_session
  local before; before=$(pane_pid)
  # Unit's cgroup must contain the tmux server for this test to be meaningful.
  local cg; cg=$(systemctl --user show -p ControlGroup --value prw-s4-agent-1)
  local srv; srv=$(tm display-message -p '#{pid}')
  grep -q "$cg" "/proc/$srv/cgroup" || { echo "FAIL: tmux server not in agent cgroup"; return 1; }

  systemctl --user stop prw-s4-agent-1          # agent stops (restart, upgrade, crash)
  agent prw-s4-agent-2 "$1" attach-only          # new agent instance
  sleep 0.5
  local after; after=$(pane_pid)
  systemctl --user stop prw-s4-agent-2 >/dev/null 2>&1 || true

  if [[ $2 == survive ]]; then
    if [[ -n $after && $after == "$before" ]]; then
      echo "PASS KillMode=$1: session survived agent restart (shell pid $before)"
    else
      echo "FAIL KillMode=$1: session lost (before=$before after=${after:-none})"; return 1
    fi
  else
    if [[ -z $after ]]; then
      echo "PASS KillMode=$1: session killed with the agent, as expected for the default"
    else
      echo "FAIL KillMode=$1: expected the session to die, still running (pid $after)"; return 1
    fi
  fi
}

run_case process survive
run_case control-group die
