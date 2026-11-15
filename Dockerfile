FROM python:3.12-alpine

WORKDIR /app
COPY requirements.txt ./
# postgresql-client is for pg_dump: the entrypoint snapshots a Postgres
# database to backups/sentriq-pg-<stamp>.dump before it serves traffic.
#
# apk upgrade first: the base image ships whatever was current when it was
# built, and postgresql-client pulls libpq, which pulls krb5-libs — 16 HIGH
# advisories in 1.22.2-r1, fixed in 1.22.3-r0. The image scan gates on HIGH, so
# a stale base is a red build, and upgrading here is the fix rather than an
# ignore file.
RUN apk upgrade --no-cache \
    && apk add --no-cache postgresql-client \
    && pip install --no-cache-dir -r requirements.txt \
    && addgroup -S app && adduser -S -G app app
COPY . .
RUN mkdir -p /app/data && chown -R app:app /app

EXPOSE 8080
USER app
ENTRYPOINT ["/app/docker-entrypoint.sh"]
