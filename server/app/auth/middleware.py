import os, json, secrets
from pathlib import Path
from datetime import datetime, timezone
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

CONFIG_DIR = Path(__file__).parent.parent.parent / "config"
KEYS_FILE = CONFIG_DIR / "api_keys.json"
EXEMPT = ["/", "/health", "/docs", "/openapi.json", "/redoc", "/dashboard", "/static", "/api/v1/auth/status"]

def _load():
    if not KEYS_FILE.exists():
        return []
    try:
        with open(KEYS_FILE) as f:
            return json.load(f).get("keys", [])
    except Exception:
        return []

def _save(keys):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(KEYS_FILE, "w") as f:
        json.dump({"keys": keys}, f, indent=2)

def is_auth_enabled():
    return os.getenv("SOVEREIGN_AUTH_ENABLED", "").lower() in ("true", "1", "yes")

def get_api_keys():
    return [k for k in _load() if k.get("active", True)]

def create_api_key(name="default"):
    entry = {
        "id": f"key_{secrets.token_hex(8)}",
        "key": f"sk_sov_{secrets.token_urlsafe(32)}",
        "name": name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "active": True,
    }
    keys = _load()
    keys.append(entry)
    _save(keys)
    return entry

def revoke_api_key(key_id):
    keys = _load()
    for k in keys:
        if k["id"] == key_id:
            k["active"] = False
            _save(keys)
            return True
    return False

class APIKeyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if not is_auth_enabled():
            return await call_next(request)
        if any(request.url.path.startswith(p) for p in EXEMPT):
            return await call_next(request)
        key = request.headers.get("X-API-Key", "")
        if not key:
            ah = request.headers.get("Authorization", "")
            if ah.startswith("Bearer "):
                key = ah[7:]
        if not key:
            return JSONResponse(401, content={"detail": "Missing API key"})
        if key not in {k["key"] for k in get_api_keys()}:
            return JSONResponse(403, content={"detail": "Invalid API key"})
        return await call_next(request)
