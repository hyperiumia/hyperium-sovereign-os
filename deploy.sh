#!/bin/bash
set -euo pipefail

# ═══════════════════════════════════════════════════
# Hyperium Sovereign-OS — Production Deploy Script
# ═══════════════════════════════════════════════════

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[x]${NC} $1"; exit 1; }

# Check prerequisites
command -v docker >/dev/null 2>&1 || err "Docker not installed"
command -v docker compose >/dev/null 2>&1 || err "Docker Compose not installed"

# Check .env
if [ ! -f .env ]; then
    if [ -f .env.production ]; then
        warn ".env not found. Copying from .env.production"
        cp .env.production .env
        warn "Please edit .env and set all CHANGE_ME values before continuing."
        exit 1
    else
        err ".env not found. Create one from .env.production template."
    fi
fi

source .env

# Validate secrets
if [[ "$POSTGRES_PASSWORD" == *"CHANGE_ME"* ]]; then
    err "POSTGRES_PASSWORD is still default. Edit .env and set a strong password."
fi
if [[ "$AGENT_HMAC_SECRET" == *"CHANGE_ME"* ]]; then
    err "AGENT_HMAC_SECRET is still default. Edit .env and set a strong secret."
fi

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   Hyperium Sovereign-OS — Production Deploy  ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
echo ""
log "Domain: ${DOMAIN:-not set}"
log "Auth: ${SOVEREIGN_AUTH_ENABLED:-false}"
log "Rate limit: ${SOVEREIGN_RATE_LIMIT:-0} rpm"
echo ""

# Build
log "Building application image..."
docker compose -f docker-compose.prod.yml build --no-cache app

# Start database first
log "Starting PostgreSQL..."
docker compose -f docker-compose.prod.yml up -d postgres
sleep 5

# Wait for database
log "Waiting for database..."
for i in $(seq 1 30); do
    if docker compose -f docker-compose.prod.yml exec -T postgres pg_isready -U sovereign -d sovereign_os >/dev/null 2>&1; then
        log "Database ready"
        break
    fi
    if [ $i -eq 30 ]; then
        err "Database failed to start after 30s"
    fi
    sleep 1
done

# Start app
log "Starting application..."
docker compose -f docker-compose.prod.yml up -d app
sleep 5

# Verify app health
log "Verifying app health..."
for i in $(seq 1 20); do
    if docker compose -f docker-compose.prod.yml exec -T app python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" >/dev/null 2>&1; then
        log "Application healthy"
        break
    fi
    if [ $i -eq 20 ]; then
        err "Application failed health check"
    fi
    sleep 2
done

# Start nginx
log "Starting nginx..."
docker compose -f docker-compose.prod.yml up -d nginx

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           Deploy complete!                    ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo ""
log "HTTP:  http://${DOMAIN:-localhost}"
log "API:   http://${DOMAIN:-localhost}/docs"
log "Health: http://${DOMAIN:-localhost}/health"
echo ""
warn "TLS not configured yet. To set up HTTPS:"
echo "  1. Edit nginx/conf.d/init-only.conf (set your domain)"
echo "  2. Run certbot:"
echo "     docker compose -f docker-compose.prod.yml run --rm certbot certonly \\"
echo "       --webroot -w /var/www/certbot \\"
echo "       --email admin@${DOMAIN:-yourdomain.com} \\"
echo "       -d ${DOMAIN:-yourdomain.com} --agree-tos --no-eff-email"
echo "  3. Edit nginx/conf.d/sovereign.conf (uncomment HTTPS block)"
echo "  4. Remove init-only.conf and restart nginx"
echo ""

# Generate first API key if auth is enabled
if [ "${SOVEREIGN_AUTH_ENABLED}" = "true" ]; then
    log "Auth is enabled. Generating initial API key..."
    RESP=$(curl -s -X POST http://localhost:8000/api/v1/auth/keys -H "Content-Type: application/json" -d '{"name": "admin-deploy"}')
    KEY=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('key','FAILED'))" 2>/dev/null || echo "FAILED")
    if [ "$KEY" != "FAILED" ]; then
        echo -e "${CYAN}  API Key: ${KEY}${NC}"
        warn "Save this key securely. It will not be shown again."
    fi
fi

log "Run 'docker compose -f docker-compose.prod.yml logs -f' to follow logs"
