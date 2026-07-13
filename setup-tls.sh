#!/bin/bash
set -euo pipefail

# ═══════════════════════════════════════════════════
# TLS Setup — Let's Encrypt via Certbot
# ═══════════════════════════════════════════════════

if [ ! -f .env ]; then
    echo "[x] .env not found. Run deploy.sh first."
    exit 1
fi

source .env

if [ -z "${DOMAIN:-}" ] || [ "$DOMAIN" == "sovereign.hyperiumia.com" ]; then
    echo "[x] Set your real domain in .env (DOMAIN=...)"
    exit 1
fi

echo "[+] Requesting TLS certificate for: $DOMAIN"

# Request certificate
docker compose -f docker-compose.prod.yml run --rm certbot certonly \
    --webroot \
    -w /var/www/certbot \
    --email "admin@$DOMAIN" \
    -d "$DOMAIN" \
    --agree-tos \
    --no-eff-email

# Update nginx config: disable init-only, enable HTTPS
if [ -f nginx/conf.d/init-only.conf ]; then
    mv nginx/conf.d/init-only.conf nginx/conf.d/init-only.conf.disabled
    echo "[+] Disabled HTTP-only fallback"
fi

# Restart nginx to load TLS config
docker compose -f docker-compose.prod.yml restart nginx

echo ""
echo "[+] TLS configured for https://$DOMAIN"
echo "[+] Auto-renewal is handled by the certbot container"
echo "[+] Verify: https://$DOMAIN/health"
