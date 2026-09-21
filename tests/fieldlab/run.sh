#!/usr/bin/env bash
# Field run: the phone reaches the lab control plane over the public internet
# (its carrier network) through a temporary Cloudflare quick tunnel, and the
# host peer runs on this machine. Exercises the WSS relay through a real CDN
# edge and ICE with public STUN on real NATs.
#
# The lab server has no authentication: the tunnel only lives for the run.
# Requires cloudflared, adb with the spike APK installed, Go.
set -euo pipefail
cd "$(dirname "$0")"
root=$(cd ../.. && pwd)
port=${PORT:-18543}
work=$(mktemp -d /tmp/prw-fieldlab.XXXXXX)
(cd "$root" && go build -o "$work/prw-labserver" ./services/control/cmd/prw-labserver \
  && go build -o "$work/prw-labpeer" ./tests/netlab/cmd/prw-labpeer)

# An empty config keeps ~/.cloudflared/config.yml (named tunnels, ingress
# rules) from overriding --url.
: > "$work/cloudflared.yml"
cloudflared --config "$work/cloudflared.yml" tunnel --no-autoupdate --url "http://127.0.0.1:$port" > "$work/tunnel.log" 2>&1 &
cf_pid=$!
cleanup() { kill $cf_pid ${ls_pid:-} 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT
url=""
for _ in $(seq 1 60); do
  url=$(grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' "$work/tunnel.log" | head -1 || true)
  [[ -n $url ]] && break; sleep 1
done
[[ -n $url ]] || { echo "tunnel did not come up"; cat "$work/tunnel.log"; exit 1; }

PRW_TURN_SHARED_SECRET=TEST-ONLY-fieldlab "$work/prw-labserver" -plain -addr "127.0.0.1:$port" \
  -public-url "$url" -stun-urls "stun:stun.l.google.com:19302" > "$work/labserver.log" 2>&1 &
ls_pid=$!
# Wait until the tunnel routes to the lab server.
ready=0
for _ in $(seq 1 90); do curl -fsS "$url/health/live" >/dev/null 2>&1 && { ready=1; break; }; sleep 1; done
[[ $ready == 1 ]] || { echo "tunnel never routed to the lab server"; exit 1; }
# New quick-tunnel names can take a while to resolve on the phone's carrier DNS.
host=${url#https://}
for _ in $(seq 1 90); do adb shell "ping -c1 -W2 $host" >/dev/null 2>&1 && break; sleep 2; done
echo "tunnel ready"

pkg=dev.prw.prw_spike
adb shell setprop log.tag.PRWSPIKE VERBOSE
adb logcat -c
adb shell am start -W -n $pkg/.MainActivity >/dev/null
sleep 2
echo "phone default network: $(adb shell dumpsys connectivity | grep -A1 'Active default network' | grep -oE 'MOBILE\[[A-Z0-9]+\]|WIFI' | head -1 || echo unknown)"

result() {
  for _ in $(seq 1 120); do
    local l; l=$(adb logcat -d -s PRWSPIKE:I | grep " $1 RESULT " | tail -1 || true)
    [[ -n $l ]] && { echo "${l#* RESULT }"; return 0; }
    sleep 1
  done
  echo '{"ok":false,"error":"no result from device"}'
}
pass=0; fail=0
run_case() { # name, mode, expect (empty = any path)
  local id="f$RANDOM$RANDOM"
  "$work/prw-labpeer" -server "$url" -role host -lab-id "$id" > "$work/host.json" 2>&1 &
  local hp=$!
  sleep 0.5
  adb shell am start -n $pkg/.MainActivity --es action run --es tag "$id" --es server "$url" \
    --es lab_id "$id" --es mode "$2" --ei bytes 1048576 >/dev/null 2>&1
  local j; j=$(result "$id")
  wait "$hp" || true
  local path; path=$(echo "$j" | sed -n 's/.*"path":"\([a-z_]*\)".*/\1/p' | head -1)
  if echo "$j" | grep -q '"ok":true' && [[ -z $3 || $path == "$3" ]]; then
    pass=$((pass+1)); echo "PASS | $1 | $(echo "$j" | cut -c1-230)"
  else
    fail=$((fail+1)); echo "FAIL | $1 | $(echo "$j" | cut -c1-400) | host: $(cut -c1-200 "$work/host.json")"
  fi
}
run_case "Field: WSS relay via Cloudflare edge (phone on carrier)" wss  wss_relay
run_case "Field: auto race with public STUN"                     auto ""
echo "passed=$pass failed=$fail"
[[ $fail == 0 ]]
