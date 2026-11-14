#!/bin/sh
# Export the audit trail, push a verified copy off this host, keep the anchor.
#
# Usage: audit-export-offhost.sh [days]
#
#   days   window to export, counted back from now (default 1). Pass 0 for
#          everything, which is what you want for the first run.
#
# Requires AUDIT_OFFHOST_DIR (a mounted share, an SFTP drop, object storage) —
# an anchor stored on the same host as the database proves nothing.
#
# Cron, daily at 01:15, on the host that runs the container:
#   15 1 * * * cd /path/to/Sentriq && docker compose exec -T sentriq \
#       sh scripts/audit-export-offhost.sh 1 >> /var/log/sentriq-audit-export.log 2>&1
set -eu

DAYS=${1:-1}
KEEP=${AUDIT_EXPORT_KEEP:-30}

if [ -z "${AUDIT_OFFHOST_DIR:-}" ]; then
    echo "audit-export-offhost: AUDIT_OFFHOST_DIR is not set; refusing to keep the anchor on this host" >&2
    exit 1
fi

if [ "$DAYS" = "0" ]; then
    WINDOW=""
else
    FROM=$(date -u -d "${DAYS} days ago" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-"${DAYS}"d +%Y-%m-%dT%H:%M:%SZ)
    WINDOW="--from ${FROM}"
fi

echo "audit-export-offhost: exporting${WINDOW:+ since $FROM} and pushing to $AUDIT_OFFHOST_DIR"

# The command verifies the copy from the destination before it reports success,
# so a failed run is a non-zero exit and cron will say so.
# shellcheck disable=SC2086
python -m sentriq.manage audit-export ${WINDOW} --push

# Prune local copies only. The off-host copy is the record and is never pruned
# by this script — retention there is the storage team's policy.
if [ -d "${AUDIT_EXPORT_DIR:-data/audit-exports}" ]; then
    ls -1t "${AUDIT_EXPORT_DIR:-data/audit-exports}"/audit-*.jsonl 2>/dev/null \
        | tail -n +$((KEEP + 1)) \
        | while read -r old; do
            rm -f "$old" "$(echo "$old" | sed 's/\.jsonl$/.manifest.json/')"
            echo "audit-export-offhost: pruned local copy $old"
        done
fi

echo "audit-export-offhost: done"
