#!/usr/bin/env bash
#
# Builds the Onserva agent for Linux.
#
# Produces a fully static binary per architecture, plus a SHA-256 checksum that
# the installer verifies before it will run anything. Static means no runtime
# dependencies at all: the same file runs on Ubuntu, Debian, Alma or Alpine
# without asking the owner to install a thing.
#
#   ./build.sh              # build the current version for amd64 and arm64
#   VERSION=0.2.0 ./build.sh
#
set -euo pipefail

cd "$(dirname "$0")"

VERSION="${VERSION:-0.1.0}"
OUT_DIR="${OUT_DIR:-dist}"
PLATFORMS=("amd64" "arm64")

command -v go >/dev/null 2>&1 || {
  echo "Go is not installed. See https://go.dev/dl/ (or: scoop install go / apt install golang-go)" >&2
  exit 1
}

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

for arch in "${PLATFORMS[@]}"; do
  name="onserva-agent-linux-${arch}"
  echo "→ building ${name} (v${VERSION})"

  # CGO_ENABLED=0  — no libc dependency, so one binary runs everywhere.
  # -trimpath      — no build-machine paths inside the binary.
  # -s -w          — strip symbols and DWARF; roughly halves the size.
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
    go build \
      -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o "${OUT_DIR}/${name}" \
      ./cmd/onserva-agent

  # The installer refuses to run a binary whose checksum does not match.
  (cd "$OUT_DIR" && sha256sum "$name" > "${name}.sha256")
done

# The installer downloads the systemd units rather than carrying its own copies,
# so there is exactly one version of each in the world — and each is checksummed,
# because a unit file is as security-critical as the binary it starts. The three
# fix-execution files are what give one root-run process the ability to restart a
# service; a tampered copy of them is a tampered privilege boundary.
for unit in onserva-agent.service onserva-fix.service onserva-fix.path onserva-tmpfiles.conf; do
  cp "deploy/${unit}" "$OUT_DIR/"
  (cd "$OUT_DIR" && sha256sum "$unit" > "${unit}.sha256")
done

echo
echo "Built into ${OUT_DIR}/:"
ls -lh "$OUT_DIR"
echo
echo "Next: publish these files at \$NEXT_PUBLIC_AGENT_DOWNLOAD_BASE so install.sh can fetch them."
