#!/bin/bash
# Point the peer's default route at its NAT router, then idle.
set -euo pipefail
ip route replace default via "$ROUTER"
exec sleep infinity
