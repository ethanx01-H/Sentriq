#!/bin/sh
# Daily retention loop for the `retention` compose service.
#
# One pass runs at startup, then once every RETENTION_INTERVAL_SECONDS (24h by
# default). A failed pass — for example, the web app's migrations have not
# finished yet, or the database is briefly unavailable — is retried after
# RETENTION_RETRY_SECONDS instead of stopping the container. The pass itself is
# idempotent and takes a Postgres advisory lock, so a retry cannot double-delete.
set -eu

INTERVAL=${RETENTION_INTERVAL_SECONDS:-86400}
RETRY=${RETENTION_RETRY_SECONDS:-300}

while true; do
    if python -m sentriq.manage retention-daily; then
        sleep "$INTERVAL"
    else
        echo "retention: pass failed; retrying in ${RETRY}s" >&2
        sleep "$RETRY"
    fi
done
