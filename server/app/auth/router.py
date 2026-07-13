from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from .middleware import get_api_keys, create_api_key, revoke_api_key, is_auth_enabled

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])

class CreateKeyRequest(BaseModel):
    name: str = "default"

@router.get("/status")
async def auth_status():
    return {"enabled": is_auth_enabled()}

@router.get("/keys")
async def list_keys():
    return [
        {"id": k["id"], "name": k["name"], "created_at": k["created_at"],
         "key_preview": k["key"][:12] + "..."}
        for k in get_api_keys()
    ]

@router.post("/keys")
async def create_key(req: CreateKeyRequest):
    e = create_api_key(req.name)
    return {**e, "message": "Save this key securely. It will not be shown again."}

@router.delete("/keys/{key_id}")
async def revoke_key(key_id: str):
    if revoke_api_key(key_id):
        return {"message": f"Key {key_id} revoked", "revoked": True}
    raise HTTPException(404, "Key not found")
