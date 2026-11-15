#!/bin/sh
# Export a published image for a host that cannot reach a registry.
#
# A bank's production network usually cannot pull from ghcr.io or from an
# internal registry it was not built to reach, and it should not need PyPI to
# build. This produces one file plus its checksum to carry across the gap:
#
#   ./scripts/save-image.sh sentriq:1.4.3 /media/transfer
#   # on the production host
#   sha256sum -c sentriq_1.4.3.tar.gz.sha256
#   gunzip -c sentriq_1.4.3.tar.gz | docker load
#   SENTRIQ_IMAGE=sentriq:1.4.3 docker compose up -d --no-build
#
# The checksum matters: an image carried on a USB stick and loaded without one
# is an unverified binary running as the SOC's system of record.
set -eu

IMAGE=${1:?usage: save-image.sh <image:tag> [output-dir]}
OUT=${2:-.}
NAME=$(printf '%s' "$IMAGE" | tr '/:' '__')
FILE="$OUT/$NAME.tar.gz"

mkdir -p "$OUT"
docker image inspect "$IMAGE" > /dev/null
docker save "$IMAGE" | gzip -9 > "$FILE"
( cd "$OUT" && sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256" )

printf '%s\n' "$FILE" "$FILE.sha256"
