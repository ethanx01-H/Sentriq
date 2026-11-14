#!/bin/sh
# Restore the newest snapshot into a scratch database and compare row counts.
#
# Usage: verify-restore.sh [backup-dir]
#
# A backup nobody restored is a guess. This restores the newest sentriq-pg-*.dump
# into a throwaway database on the same server, compares the row counts of every
# table against the live database, and drops the scratch database again. It is
# safe to run against production: nothing is written to the live database.
#
# Exit codes: 0 the restore matches, 1 the restore failed or disagrees.
#
# Cron, weekly on Sunday at 03:30:
#   30 3 * * 0 cd /path/to/Sentriq && docker compose exec -T sentriq \
#       sh scripts/verify-restore.sh /app/backups >> /var/log/sentriq-restore.log 2>&1
set -eu

BACKUP_DIR=${1:-backups}
SOURCE_URL=${DATABASE_URL:?DATABASE_URL must be set}

# pg_dump writes a libpq connection string; strip the SQLAlchemy driver suffix.
url=$(printf '%s' "$SOURCE_URL" | sed 's/^postgresql+psycopg2*:/postgresql:/; s/^postgres+psycopg2*:/postgresql:/')

newest=$(ls -1t "$BACKUP_DIR"/sentriq-pg-*.dump 2>/dev/null | head -n 1 || true)
if [ -z "$newest" ]; then
    echo "verify-restore: no sentriq-pg-*.dump in $BACKUP_DIR" >&2
    exit 1
fi

scratch="sentriq_restore_check_$(date -u +%Y%m%d%H%M%S)"
# Replace only the database name: the part after "?" can carry host=/socket/dir
# (which is how the bundled Postgres is addressed) and must not be touched.
base=${url%%\?*}
query=""
case "$url" in
    *\?*) query="?${url#*\?}" ;;
esac
scratch_url=$(printf '%s' "$base" | sed -E "s#(.*/)[^/]+\$#\1${scratch}#")${query}

cleanup() {
    psql "$url" -q -c "drop database if exists \"$scratch\"" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "verify-restore: restoring $(basename "$newest") into $scratch"
psql "$url" -q -v ON_ERROR_STOP=1 -c "create database \"$scratch\"" >/dev/null

if ! pg_restore --no-owner --no-privileges --exit-on-error -d "$scratch_url" "$newest"; then
    echo "verify-restore: FAILED — the snapshot does not restore" >&2
    exit 1
fi

status=0
for table in fastapi_users fastapi_alerts fastapi_alert_events fastapi_evidence fastapi_audit_logs fastapi_sla_breaches; do
    live=$(psql "$url" -tA -c "select count(*) from $table" 2>/dev/null || echo "missing")
    restored=$(psql "$scratch_url" -tA -c "select count(*) from $table" 2>/dev/null || echo "missing")

    if [ "$restored" = "missing" ]; then
        echo "verify-restore: FAILED — $table is missing from the restored copy" >&2
        status=1
        continue
    fi
    # The snapshot was taken before the live database's newest writes, so the
    # restored copy can be behind; it can never be ahead, and it must not be
    # empty when the source is not.
    if [ "$live" != "missing" ] && [ "$restored" -gt "$live" ]; then
        echo "verify-restore: FAILED — $table restored $restored rows, live has $live" >&2
        status=1
    elif [ "$live" != "missing" ] && [ "$live" -gt 0 ] && [ "$restored" -eq 0 ]; then
        echo "verify-restore: FAILED — $table is empty in the restored copy, $live rows live" >&2
        status=1
    else
        printf 'verify-restore: %-24s restored %-8s live %s\n' "$table" "$restored" "$live"
    fi
done

if [ "$status" -eq 0 ]; then
    echo "verify-restore: OK — the newest snapshot restores and matches the live database"
else
    echo "verify-restore: the restore does not match; do not trust this backup" >&2
fi
exit "$status"
