#!/usr/bin/env bash
# PRW network lab (spikes S2 and S3). Builds the lab binaries, starts the
# topology in compose.yaml and runs one full connection attempt per scenario,
# checking which path the connection manager selected.
#
#   ./run.sh            run all scenarios, then tear down
#   KEEP=1 ./run.sh     leave the lab running afterwards
set -euo pipefail
cd "$(dirname "$0")"
root=$(cd ../.. && pwd)


mkdir -p .lab/bin
(cd "$root" && CGO_ENABLED=0 go build -o tests/netlab/.lab/bin/prw-labserver ./services/control/cmd/prw-labserver \
  && CGO_ENABLED=0 go build -o tests/netlab/.lab/bin/prw-labpeer ./tests/netlab/cmd/prw-labpeer)
./gen-certs.sh .lab/certs >/dev/null

dc() { docker compose "$@"; }
dc up -d --build --quiet-pull >/dev/null 2>&1 || dc up -d --build
trap '[[ ${KEEP:-0} == 1 ]] || dc down -v --remove-orphans >/dev/null 2>&1' EXIT

for _ in $(seq 1 50); do
  dc exec -T phone true 2>/dev/null && dc exec -T host true 2>/dev/null && break; sleep 0.2
done
sleep 1

results=()
pass=0; fail=0
scenario() { # name, phone-nat, host-nat, expect, extra phone flags...
  # PHONE / HOST select the peer containers (default: phone, host).
  local name=$1 pnat=$2 hnat=$3 expect=$4; shift 4
  local P=${PHONE:-phone} H=${HOST:-host}
  dc exec -T router-p /lab/config/router.sh "$pnat" >/dev/null
  dc exec -T router-h /lab/config/router.sh "$hnat" >/dev/null
  dc exec -T "$H" pkill -f prw-labpeer 2>/dev/null || true
  local id="s$RANDOM$RANDOM"
  dc exec -T -d "$H" sh -c "/lab/bin/prw-labpeer -role host -lab-id $id -server https://api.lab.invalid > /tmp/host.json 2>&1"
  sleep 0.5
  local out rc=0
  out=$(dc exec -T "$P" timeout 90 /lab/bin/prw-labpeer -role phone -lab-id "$id" -server https://api.lab.invalid \
        -bytes 2097152 -expect "$expect" "$@" 2>&1) || rc=$?
  sleep 0.5
  local host; host=$(dc exec -T "$H" cat /tmp/host.json 2>/dev/null | tail -1)
  local line; line=$(echo "$out" | tail -1)
  local path ms rtt mbps pair
  path=$(echo "$line" | sed -n 's/.*"path":"\([a-z_]*\)".*/\1/p' | head -1)
  ms=$(echo "$line" | sed -n 's/.*"connect_ms":\([0-9]*\).*/\1/p')
  rtt=$(echo "$line" | sed -n 's/.*"rtt_ms":\([0-9.]*\).*/\1/p' | cut -c1-5)
  mbps=$(echo "$line" | sed -n 's/.*"mbps":\([0-9.]*\).*/\1/p' | cut -c1-6)
  pair=$(echo "$line" | sed -n 's/.*"ice_pair":"\([^"]*\)".*/\1/p')
  if [[ $rc == 0 ]] && echo "$host" | grep -q '"ok":true'; then
    pass=$((pass+1)); results+=("PASS | $name | expect=$expect got=$path | connect=${ms}ms rtt=${rtt}ms echo=${mbps}Mbit/s ${pair:+ice=[$pair]}")
  else
    fail=$((fail+1)); results+=("FAIL | $name | expect=$expect got=${path:-none} | phone: $(echo "$line" | cut -c1-240) | host: $(echo "$host" | cut -c1-200)")
  fi
}

PHONE=phone-lan scenario "S2 same LAN -> direct host candidates" cone cone direct
HOST=host-pub   scenario "S2 NATed phone -> public host: direct"   cone cone direct
# Linux NAT is port-restricted and early inbound hole-punch packets create
# conntrack entries that force a remap, so simultaneous open fails here and
# ICE must fall back to TURN. Real home routers vary; this checks the fallback.
scenario "S2 two Linux port-restricted NATs -> TURN" cone      cone      turn
scenario "S2 symmetric NATs fall back to TURN/UDP"   symmetric   symmetric turn
scenario "S2 forced relay (TURN only)"               cone        cone      turn      -force-relay
scenario "S2 phone UDP blocked -> TURN over TCP/TLS" udp-blocked cone      turn
scenario "S2 phone TCP/443 only -> TURN-TLS on EIP-B:443" tcp443-only cone turn
scenario "S3 HTTPS proxy only (DPI) -> WSS relay"    proxy-only  cone      wss_relay -proxy http://proxy.lab.invalid:3128
scenario "S3 proxy only, UDP-blocked hint -> WSS at t=0" proxy-only cone    wss_relay -proxy http://proxy.lab.invalid:3128 -udp-blocked
dc stop turn >/dev/null 2>&1
scenario "S3 TURN down + UDP blocked -> WSS relay"   udp-blocked cone      wss_relay
dc start turn >/dev/null 2>&1

echo
echo "relay stats: $(dc exec -T phone sh -c 'wget -qO- https://api.lab.invalid/lab/stats 2>/dev/null' || echo n/a)"
printf '%s\n' "${results[@]}"
echo "passed=$pass failed=$fail"
[[ $fail == 0 ]]
