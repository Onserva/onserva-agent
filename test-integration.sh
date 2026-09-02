#!/usr/bin/env bash
#
# Integration-tests the dbstat wire clients against real engines.
#
# Starts PostgreSQL, MariaDB and Redis containers with their unix sockets on
# shared volumes, then runs `go test -tags integration ./internal/dbstat/`
# inside a golang container with those sockets mounted at the agent's
# compiled-in locations. The point: the hand-rolled protocol clients are only
# trustworthy once a real server has answered them.
#
#   ./test-integration.sh          # full run, cleans up after itself
#
set -euo pipefail
cd "$(dirname "$0")"

# Git Bash on Windows rewrites /container/paths into C:/Program Files/… before
# docker ever sees them, which quietly breaks every -v and every in-container
# argument. Both variables are needed: one for MSYS2, one for older msys.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

PG=onserva-it-pg MY=onserva-it-my RD=onserva-it-rd
VOL_PG=onserva-it-pg-sock VOL_MY=onserva-it-my-sock VOL_RD=onserva-it-rd-sock

cleanup() {
  docker rm -f "$PG" "$MY" "$RD" >/dev/null 2>&1 || true
  docker volume rm "$VOL_PG" "$VOL_MY" "$VOL_RD" >/dev/null 2>&1 || true
}
cleanup
trap cleanup EXIT

# The test process runs as root inside the golang container, so the engines
# are set up to accept a local root connection with an EMPTY credential —
# which is exactly the only thing the clients know how to send.
docker run -d --name "$PG" -v "$VOL_PG":/var/run/postgresql \
  -e POSTGRES_USER=root -e POSTGRES_PASSWORD=integration-only postgres:16 >/dev/null
docker run -d --name "$MY" -v "$VOL_MY":/run/mysqld \
  -e MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=1 mariadb:11 >/dev/null
# The fresh volume arrives root-owned and the image drops to the redis user,
# so hand the socket directory over before the entrypoint switches identity.
docker run -d --name "$RD" -v "$VOL_RD":/sock redis:7 \
  sh -c 'chown redis:redis /sock && exec docker-entrypoint.sh redis-server --unixsocket /sock/redis.sock --unixsocketperm 777' >/dev/null

echo "waiting for the engines to come up…"
for i in $(seq 1 60); do
  ready=0
  docker exec "$PG" pg_isready -q 2>/dev/null && ready=$((ready+1)) || true
  docker exec "$MY" mariadb-admin ping --silent 2>/dev/null && ready=$((ready+1)) || true
  docker exec "$RD" redis-cli -s /sock/redis.sock ping 2>/dev/null | grep -q PONG && ready=$((ready+1)) || true
  [ "$ready" = 3 ] && break
  sleep 1
done
[ "${ready:-0}" = 3 ] || { echo "engines did not come up"; exit 1; }

docker run --rm \
  -v "$(pwd)":/src -w /src \
  -v "$VOL_PG":/var/run/postgresql \
  -v "$VOL_MY":/var/run/mysqld \
  -v "$VOL_RD":/var/run/redis \
  -e ONSERVA_INTEGRATION_DETECT=1 \
  golang:1.24 \
  sh -c 'ln -sf /var/run/redis/redis.sock /var/run/redis/redis-server.sock 2>/dev/null; go test -tags integration -count=1 -v ./internal/dbstat/'
