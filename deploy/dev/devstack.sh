#!/usr/bin/env bash
# Local development stack: PostgreSQL (Docker), the control plane, and a
# Cloudflare quick tunnel giving it a public https URL for the phone.
#
#   deploy/dev/devstack.sh up        start everything, print the public URL
#   deploy/dev/devstack.sh down      stop it (database volume is kept)
#
# Reads Google client IDs from ./.env (GOOGLE_WEB_CLIENT_ID or the
# GOOGLE_WEN_CLIENT_ID spelling). Keys and secrets live outside the repo in
# $PRW_DEV_HOME (default ~/.local/share/prw-dev). The allowlist comes from
# $PRW_DEV_HOME/allowed_subjects (one google:<sub> per line).
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
home=${PRW_DEV_HOME:-$HOME/.local/share/prw-dev}
port=${PRW_DEV_PORT:-18080}
mkdir -p "$home" && chmod 700 "$home"

webid=$(grep -E '^GOOGLE_WE[BN]_CLIENT_ID=' "$root/.env" | head -1 | cut -d= -f2-)
[[ -n $webid ]] || { echo "GOOGLE_WEB_CLIENT_ID missing in .env"; exit 1; }

down() {
  [[ -f $home/control.pid ]] && kill "$(cat "$home/control.pid")" 2>/dev/null || true
  [[ -f $home/tunnel.pid ]] && kill "$(cat "$home/tunnel.pid")" 2>/dev/null || true
  rm -f "$home/control.pid" "$home/tunnel.pid"
  docker stop prw-dev-db >/dev/null 2>&1 || true
}

up() {
  # Database (persistent volume prw-dev-pg).
  if ! docker ps --format '{{.Names}}' | grep -qx prw-dev-db; then
    docker rm -f prw-dev-db >/dev/null 2>&1 || true
    [[ -f $home/db_password ]] || (head -c 24 /dev/urandom | base64 | tr -d '/+=' > "$home/db_password" && chmod 600 "$home/db_password")
    docker run -d --name prw-dev-db -v prw-dev-pg:/var/lib/postgresql/data -p 127.0.0.1:55432:5432 \
      -e POSTGRES_USER=prw -e POSTGRES_PASSWORD="$(cat "$home/db_password")" -e POSTGRES_DB=prw postgres:16-alpine >/dev/null
  fi
  for _ in $(seq 1 60); do docker exec prw-dev-db pg_isready -U prw >/dev/null 2>&1 && break; sleep 0.5; done

  # Keys and secrets (generated once).
  [[ -f $home/secrets/access_signing_key.pem ]] || (cd "$root" && go run ./services/control/cmd/prw-control keygen "$home/secrets")
  printf 'postgres://prw:%s@127.0.0.1:55432/prw?sslmode=disable' "$(cat "$home/db_password")" > "$home/secrets/database_url"
  chmod 600 "$home/secrets/database_url"
  touch "$home/allowed_subjects"

  # Tunnel first: the public URL is part of the server's configuration.
  if [[ ! -f $home/tunnel.pid ]] || ! kill -0 "$(cat "$home/tunnel.pid")" 2>/dev/null; then
    : > "$home/cloudflared.yml"
    cloudflared --config "$home/cloudflared.yml" tunnel --no-autoupdate --url "http://127.0.0.1:$port" > "$home/tunnel.log" 2>&1 &
    echo $! > "$home/tunnel.pid"
    for _ in $(seq 1 60); do grep -qo 'https://[a-z0-9-]*\.trycloudflare\.com' "$home/tunnel.log" && break; sleep 1; done
  fi
  url=$(grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' "$home/tunnel.log" | head -1)
  [[ -n $url ]] || { echo "tunnel did not start"; cat "$home/tunnel.log"; exit 1; }
  echo "$url" > "$home/public_url"

  # Control plane (restarted on every `up` to pick up allowlist changes).
  [[ -f $home/control.pid ]] && kill "$(cat "$home/control.pid")" 2>/dev/null || true
  (cd "$root" && go build -o "$home/prw-control" ./services/control/cmd/prw-control)
  allowed=$( (grep -E '^google:' "$home/allowed_subjects" || true) | paste -sd, -)
  [[ -n $allowed ]] || allowed="google:nobody-yet"   # sign in once; the denied subject is logged
  PRW_PUBLIC_BASE_URL="$url" PRW_LISTEN_ADDR="127.0.0.1:$port" \
  PRW_DATABASE_URL_FILE="$home/secrets/database_url" PRW_GOOGLE_CLIENT_IDS="$webid" PRW_ALLOWED_SUBJECTS="$allowed" \
  PRW_ACCESS_SIGNING_KEY_FILE="$home/secrets/access_signing_key.pem" PRW_TICKET_SIGNING_KEY_FILE="$home/secrets/ticket_signing_key.pem" \
  PRW_PAIRING_HMAC_KEY_FILE="$home/secrets/pairing_hmac_key" PRW_TURN_SHARED_SECRET_FILE="$home/secrets/turn_shared_secret" \
  PRW_TURN_URLS="turn:127.0.0.1:3478?transport=udp" PRW_STUN_URLS="stun:stun.l.google.com:19302" \
    "$home/prw-control" serve >> "$home/control.log" 2>&1 &
  echo $! > "$home/control.pid"
  for _ in $(seq 1 60); do curl -fsS "$url/health/ready" >/dev/null 2>&1 && break; sleep 1; done
  curl -fsS "$url/health/ready" >/dev/null && echo "control plane: $url" || { echo "not ready; see $home/control.log"; tail -5 "$home/control.log"; exit 1; }
}

case ${1:-up} in
  up) up ;;
  down) down ;;
  *) echo "usage: $0 up|down"; exit 2 ;;
esac
