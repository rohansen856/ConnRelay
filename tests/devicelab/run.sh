#!/usr/bin/env bash
# On-device transport spike (S1/S6): a real Android phone runs the phone side
# of each attempt in-process (Flutter app + gomobile prwcore); this machine
# runs the lab control plane, coturn and the host peer on its LAN address.
#
#   LAN_IP=10.0.0.5 ./run.sh        # phone must reach LAN_IP (same Wi-Fi/hotspot)
#
# Requires: adb with one device, the spike APK installed (see
# apps/mobile_spike/build-aar.sh and `flutter build apk`), docker, Go.
set -euo pipefail
cd "$(dirname "$0")"
root=$(cd ../.. && pwd)
: "${LAN_IP:?set LAN_IP to this machine's address on the phone's network}"
port=${PORT:-18443}
work=$(mktemp -d /tmp/prw-devicelab.XXXXXX)

(cd "$root" && go build -o "$work/prw-labserver" ./services/control/cmd/prw-labserver \
  && go build -o "$work/prw-labpeer" ./tests/netlab/cmd/prw-labpeer)

sed "s/@LAN_IP@/$LAN_IP/g" turnserver.conf.in > "$work/turnserver.conf"
docker rm -f prw-devicelab-turn >/dev/null 2>&1 || true
docker run -d --name prw-devicelab-turn --network host \
  -v "$work/turnserver.conf:/etc/coturn/turnserver.conf:ro" coturn/coturn:4.18.0 -c /etc/coturn/turnserver.conf >/dev/null

PRW_TURN_SHARED_SECRET=TEST-ONLY-devicelab-secret "$work/prw-labserver" -plain -addr "$LAN_IP:$port" \
  -public-url "http://$LAN_IP:$port" -stun-urls "stun:$LAN_IP:3478" \
  -turn-urls "turn:$LAN_IP:3478?transport=udp,turn:$LAN_IP:3478?transport=tcp" > "$work/labserver.log" 2>&1 &
ls_pid=$!
cleanup() { kill $ls_pid 2>/dev/null || true; pkill -f "$work/prw-labpeer" 2>/dev/null || true
            docker rm -f prw-devicelab-turn >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT
sleep 1

pkg=dev.prw.prw_spike
# Some OEM builds drop app INFO logs unless the tag level is raised.
adb shell setprop log.tag.PRWSPIKE VERBOSE
adb logcat -c
adb shell am force-stop $pkg
adb shell am start -W -n $pkg/.MainActivity >/dev/null
sleep 2

result() { # waits for the tagged result line in logcat
  local tag=$1
  for _ in $(seq 1 120); do
    local l; l=$(adb logcat -d -s PRWSPIKE:I | grep " $tag RESULT " | tail -1 || true)
    [[ -n $l ]] && { echo "${l#* RESULT }"; return 0; }
    sleep 1
  done
  echo '{"ok":false,"error":"no result from device"}'
}

pass=0; fail=0
check() { # name, json, expect-path
  local name=$1 json=$2 expect=$3 ok path
  ok=$(echo "$json" | grep -o '"ok":true' || true)
  path=$(echo "$json" | sed -n 's/.*"path":"\([a-z_]*\)".*/\1/p' | head -1)
  if [[ -n $ok && ( -z $expect || $path == "$expect" ) ]]; then
    pass=$((pass+1)); echo "PASS | $name | $(echo "$json" | cut -c1-260)"
  else
    fail=$((fail+1)); echo "FAIL | $name | $(echo "$json" | cut -c1-400)"
  fi
}

adb shell am start -n $pkg/.MainActivity --es action check_key --es tag s6 >/dev/null
check "S6 hardware-backed P-256 key signs, Go verifies" "$(result s6)" ""

run_case() { # name, mode, force_relay, expect
  local id="d$RANDOM$RANDOM"
  "$work/prw-labpeer" -server "http://$LAN_IP:$port" -role host -lab-id "$id" > "$work/host.json" 2>&1 &
  local host_pid=$!
  sleep 0.3
  adb shell am start -n $pkg/.MainActivity --es action run --es tag "$id" --es server "http://$LAN_IP:$port" \
    --es lab_id "$id" --es mode "$2" --ez force_relay "$3" --ei bytes 4194304 >/dev/null
  check "$1" "$(result "$id")" "$4"
  wait "$host_pid" || true
}
run_case "S1 phone->host direct over Wi-Fi (Pion via gomobile)" webrtc false direct
run_case "S1 forced TURN relay"                                   webrtc true  turn
run_case "S1 WSS relay with inner TLS 1.3"                       wss    false wss_relay
run_case "S1 auto (connection manager race)"                     auto   false direct
echo "passed=$pass failed=$fail"
[[ $fail == 0 ]]
