#!/bin/sh
# Build the image and scan it for known vulnerabilities and misconfiguration.
#
# Usage: scan-image.sh [image-tag]
#
# Needs Docker and trivy (https://aquasecurity.github.io/trivy/). CI runs the
# same two scans, so a local pass means the pipeline will pass the scan step too.
set -eu

IMAGE=${1:-sentriq:local}
SEVERITY=${SEVERITY:-HIGH,CRITICAL}

if ! command -v trivy >/dev/null 2>&1; then
    echo "scan-image: trivy is not installed" >&2
    echo "  macOS:  brew install trivy" >&2
    echo "  Linux:  see https://aquasecurity.github.io/trivy/latest/getting-started/installation/" >&2
    exit 1
fi

echo "scan-image: building $IMAGE"
docker build -t "$IMAGE" .

echo "scan-image: scanning the image for $SEVERITY vulnerabilities"
# ignore-unfixed keeps the build honest: there is nothing to do about a CVE with
# no released fix, and failing on it trains people to ignore the scanner.
trivy image --severity "$SEVERITY" --ignore-unfixed --exit-code 1 "$IMAGE"

echo "scan-image: scanning the repository configuration"
trivy config --severity "$SEVERITY" --exit-code 1 .

echo "scan-image: clean"
