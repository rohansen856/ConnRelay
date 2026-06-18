#!/bin/bash
# Configure a lab NAT router. Usage: router.sh <mode>
#   cone        endpoint-independent mapping (Linux MASQUERADE keeps ports)
#   symmetric   endpoint-dependent mapping (MASQUERADE --random-fully)
#   udp-blocked cone, but all UDP from the LAN is dropped
#   proxy-only  only TCP to the HTTPS proxy is forwarded (DPI-style egress)
#   tcp443-only only TCP port 443 is forwarded (no UDP, no other ports)
set -euo pipefail
mode=$1
wan=$(ip -o -4 addr show | awk '/10\.99\.0\./ {print $2}')
lan=$(ip -o -4 addr show | awk '/10\.98\./ {print $2}')
iptables -F FORWARD; iptables -t nat -F POSTROUTING
iptables -P FORWARD DROP
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
case $mode in
  cone)        iptables -t nat -A POSTROUTING -o "$wan" -j MASQUERADE
               iptables -A FORWARD -i "$lan" -o "$wan" -j ACCEPT ;;
  symmetric)   iptables -t nat -A POSTROUTING -o "$wan" -j MASQUERADE --random-fully
               iptables -A FORWARD -i "$lan" -o "$wan" -j ACCEPT ;;
  udp-blocked) iptables -t nat -A POSTROUTING -o "$wan" -j MASQUERADE
               iptables -A FORWARD -i "$lan" -p udp -j DROP
               iptables -A FORWARD -i "$lan" -o "$wan" -j ACCEPT ;;
  proxy-only)  iptables -t nat -A POSTROUTING -o "$wan" -j MASQUERADE
               iptables -A FORWARD -i "$lan" -o "$wan" -p tcp -d 10.99.0.30 --dport 3128 -j ACCEPT ;;
  tcp443-only) iptables -t nat -A POSTROUTING -o "$wan" -j MASQUERADE
               iptables -A FORWARD -i "$lan" -o "$wan" -p tcp --dport 443 -j ACCEPT ;;
  *) echo "unknown mode $mode"; exit 2 ;;
esac
conntrack -F 2>/dev/null || true
echo "router $(hostname): $mode (lan=$lan wan=$wan)"
