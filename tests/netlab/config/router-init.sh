#!/bin/bash
set -euo pipefail
/lab/config/router.sh "${NAT_MODE:-cone}"
exec sleep infinity
