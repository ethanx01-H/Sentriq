# Sentriq deployment guide — 152.42.171.187

This is the host-specific runbook for the production deployment on the
DigitalOcean droplet. For the generic project documentation see
[README.md](../README.md) and [nginx.conf](../nginx.conf).

## Layout

```
Internet
  │  80 / 443
  ▼
Nginx (host)  ── proxy ──►  127.0.0.1:8080  (Docker, loopback only)
                                  │
                                  ├── sentriq     gunicorn + uvicorn worker
                                  ├── retention   daily archive/delete job
                                  └── postgres    data in ./pgdata
```

- Host: `152.42.171.187` (Ubuntu 24.04, hostname `ubuntu-s-1vcpu-1gb-sgp1`)
- Checkout: `/root/Sentriq`
- Public URL: `https://152.42.171.187` — self-signed certificate, so the
  browser shows a warning once; choose **Advanced → Proceed**.
- The app is **not** reachable on `:8080` from outside; only Nginx is exposed.

## Files that matter

| Path | Purpose |
| --- | --- |
| `/root/Sentriq/.env` | Secrets and runtime config, mode `600 root:root` |
| `/root/Sentriq/docker-compose.yml` | Stack definition |
| `/root/Sentriq/data/` | Uploaded evidence (owned by `100:101`) |
| `/root/Sentriq/backups/` | `pg_dump` snapshots (owned by `100:101`) |
| `/root/Sentriq/pgdata/` | Postgres data directory (leave ownership alone) |
| `/etc/nginx/sites-available/sentriq` | Reverse-proxy site |
| `/etc/ssl/certs/sentriq.crt`, `/etc/ssl/private/sentriq.key` | Self-signed TLS cert/key |

## Required `.env` values

```ini
APP_ENV=production
COOKIE_SECURE=1
ALLOWED_HOSTS=152.42.171.187,127.0.0.1,localhost
PUBLIC_BASE_URL=https://152.42.171.187
TRUSTED_PROXIES=172.18.0.1/32          # `docker network inspect sentriq_default` gateway
FORWARDED_ALLOW_IPS=172.18.0.1/32      # set via compose from TRUSTED_PROXIES
APP_SECRET_KEY=<openssl rand -hex 32>
DATABASE_URL=postgresql://sentriq:<password>@postgres:5432/sentriq
POSTGRES_PASSWORD=<same password>
EVIDENCE_ENCRYPTION_KEY=<openssl rand -hex 32>
```

`FORWARDED_ALLOW_IPS` must include the Docker gateway. Without it Uvicorn
ignores `X-Forwarded-Proto`, the app builds `http://` asset URLs on an
`https://` page, and the browser blocks the CSS/JS — the login page appears
unstyled.

## First-time setup (what was done)

```bash
cd /root/Sentriq
cp .env.example .env
chmod 600 .env
# edit .env with the values above

# The container runs as uid/gid 100/101; the bind mounts must be writable.
mkdir -p data backups
chown -R 100:101 data backups
chmod 750 data backups

# TLS (self-signed for the IP; replace with Let's Encrypt once a domain exists)
openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
  -keyout /etc/ssl/private/sentriq.key -out /etc/ssl/certs/sentriq.crt \
  -subj "/CN=152.42.171.187" -addext "subjectAltName=IP:152.42.171.187"
chmod 600 /etc/ssl/private/sentriq.key

# Nginx
cp nginx.conf /etc/nginx/sites-available/sentriq
# edit server_name and ssl_certificate paths for this host
ln -sf /etc/nginx/sites-available/sentriq /etc/nginx/sites-enabled/sentriq
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl enable --now nginx

# Stack
docker compose up -d --build

# First administrator (prompts for the password twice)
docker compose exec -T sentriq python -m sentriq.manage create-admin admin_l3
```

## Daily operations

```bash
cd /root/Sentriq

docker compose ps                       # service health
docker compose logs -f sentriq          # application log
docker compose logs --tail=50 retention # retention job
curl -fsS http://127.0.0.1:8080/healthz # database + backup freshness
curl -fsSk https://152.42.171.187/healthz

docker compose restart sentriq          # restart the app only
docker compose down                     # stop the stack (data stays on disk)
docker compose up -d                    # start it again
```

After changing `.env`:

```bash
docker compose up -d --force-recreate sentriq
```

### Updating the application

```bash
cd /root/Sentriq
git pull --ff-only
docker compose up -d --build
docker compose logs -f sentriq
```

## Backups

The entrypoint writes `backups/sentriq-pg-<stamp>.dump` before every start.
That is not enough on its own — schedule a daily snapshot:

```bash
(crontab -l 2>/dev/null; echo '0 2 * * * cd /root/Sentriq && docker compose exec -T sentriq sh scripts/backup-postgres.sh /app/backups 30 0 >> /var/log/sentriq-backup.log 2>&1') | crontab -
```

Check the newest snapshot:

```bash
docker compose exec -T sentriq python -m sentriq.manage backup-status
```

Restore:

```bash
docker compose exec -T sentriq sh scripts/verify-restore.sh /app/backups
```

**Back up `.env` separately and securely.** It holds `APP_SECRET_KEY`,
`EVIDENCE_ENCRYPTION_KEY` and the database password. Losing
`EVIDENCE_ENCRYPTION_KEY` makes encrypted evidence unrecoverable.

## Firewall

Allow only:

- `22/tcp` — SSH (restrict to your own address if possible)
- `80/tcp` — HTTP, redirects to HTTPS
- `443/tcp` — HTTPS

Do **not** open `8080`. The compose file binds it to `127.0.0.1` on purpose.
UFW is inactive on this host; the DigitalOcean cloud firewall is the gate.

## Moving to a real domain + trusted certificate

1. Point DNS: `sentriq.yourdomain.com  A  152.42.171.187`
2. Issue the certificate (port 80 must be reachable):

   ```bash
   apt install -y certbot
   systemctl stop nginx
   certbot certonly --standalone -d sentriq.yourdomain.com
   ```

3. Update the Nginx site:

   ```bash
   sed -i 's|152\.42\.171\.187|sentriq.yourdomain.com|g' /etc/nginx/sites-available/sentriq
   sed -i 's|/etc/ssl/certs/sentriq.crt|/etc/letsencrypt/live/sentriq.yourdomain.com/fullchain.pem|' /etc/nginx/sites-available/sentriq
   sed -i 's|/etc/ssl/private/sentriq.key|/etc/letsencrypt/live/sentriq.yourdomain.com/privkey.pem|' /etc/nginx/sites-available/sentriq
   nginx -t && systemctl start nginx
   ```

4. Update `.env` and recreate:

   ```bash
   sed -i 's|^ALLOWED_HOSTS=.*|ALLOWED_HOSTS=sentriq.yourdomain.com,127.0.0.1|' .env
   sed -i 's|^PUBLIC_BASE_URL=.*|PUBLIC_BASE_URL=https://sentriq.yourdomain.com|' .env
   docker compose up -d --force-recreate sentriq
   ```

5. Add the HSTS header back to the Nginx site once the certificate is trusted.

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| Container `Restarting (1)` | Read `docker compose logs sentriq`; usually a config guard (`APP_SECRET_KEY` placeholder, `COOKIE_SECURE=0` in production, missing `ALLOWED_HOSTS` or `TRUSTED_PROXIES`) or the permissions issue below. |
| `PermissionError: /app/data/evidence` | `chown -R 100:101 data backups` on the host. |
| `pg_dump ... Permission denied` | Same ownership fix for `backups`. |
| Login page unstyled / no CSS | `FORWARDED_ALLOW_IPS` does not include the Docker gateway; set it from `TRUSTED_PROXIES` and recreate. Hard-refresh the browser. |
| `400 Bad Request` | `ALLOWED_HOSTS` does not contain the requested hostname. |
| `502 Bad Gateway` from Nginx | The app is not healthy: `docker compose ps`, `docker compose logs sentriq`. |
| `Connection refused` on `:8080` from outside | Expected: the port is loopback-only; use HTTPS through Nginx. |
| Certificate warning | Expected with the self-signed cert; move to a domain as above. |

## Security checklist

- [ ] `admin_l3` password changed from the generated one
- [ ] `.env` backed up somewhere safe (not only on this host)
- [ ] Cloud firewall allows only 22/80/443
- [ ] Daily `pg_dump` cron installed
- [ ] `EVIDENCE_ENCRYPTION_KEY` recorded in the secrets store
- [ ] Plan to replace the self-signed certificate with a trusted one
