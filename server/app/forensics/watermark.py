"""Cryptographic Watermarking — Embeds invisible forensic markers in documents."""
import hashlib
import hmac
import json
import base64
import uuid
from datetime import datetime, timezone
import structlog

logger = structlog.get_logger("forensics.watermark")

WATERMARK_SECRET = "sovereign-os-watermark-v1"


class DocumentWatermarker:

    @staticmethod
    def generate_watermark(user_id: str, document_id: str, workspace_id: str = None):
        watermark_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        payload = {
            "wid": watermark_id,
            "uid": user_id,
            "did": document_id,
            "ws": workspace_id,
            "ts": timestamp,
        }

        payload_json = json.dumps(payload, sort_keys=True)
        signature = hmac.new(
            WATERMARK_SECRET.encode(),
            payload_json.encode(),
            hashlib.sha256
        ).hexdigest()[:32]

        payload["sig"] = signature
        encoded = base64.b64encode(json.dumps(payload).encode()).decode()

        watermark = {
            "watermark_id": watermark_id,
            "user_id": user_id,
            "document_id": document_id,
            "workspace_id": workspace_id,
            "timestamp": timestamp,
            "watermark_token": encoded,
            "signature": signature,
            "verification_url": f"/api/v1/forensics/watermark/verify?token={encoded}",
        }

        logger.info("watermark.generated",
                     watermark_id=watermark_id,
                     user_id=user_id,
                     document_id=document_id)
        return watermark

    @staticmethod
    def verify_watermark(token: str):
        try:
            decoded = json.loads(base64.b64decode(token).decode())
            stored_sig = decoded.pop("sig", None)
            if not stored_sig:
                return {"valid": False, "reason": "No signature in watermark"}

            payload_json = json.dumps(decoded, sort_keys=True)
            expected_sig = hmac.new(
                WATERMARK_SECRET.encode(),
                payload_json.encode(),
                hashlib.sha256
            ).hexdigest()[:32]

            if not hmac.compare_digest(stored_sig, expected_sig):
                return {"valid": False, "reason": "Signature mismatch — watermark tampered"}

            return {
                "valid": True,
                "watermark_id": decoded.get("wid"),
                "user_id": decoded.get("uid"),
                "document_id": decoded.get("did"),
                "workspace_id": decoded.get("ws"),
                "timestamp": decoded.get("ts"),
            }
        except Exception as e:
            return {"valid": False, "reason": f"Invalid watermark: {str(e)}"}

    @staticmethod
    def embed_in_text(content: str, watermark_token: str):
        zero_width_chars = {
            '0': '\u200b',
            '1': '\u200c',
        }
        binary = ''.join(format(ord(c), '08b') for c in watermark_token[:32])
        hidden = ''.join(zero_width_chars[b] for b in binary)
        return content + hidden

    @staticmethod
    def embed_in_json(data: dict, user_id: str, document_id: str, workspace_id: str = None):
        wm = DocumentWatermarker.generate_watermark(user_id, document_id, workspace_id)
        data["_sovereign_watermark"] = {
            "token": wm["watermark_token"],
            "generated": wm["timestamp"],
        }
        return data

    @staticmethod
    def extract_from_json(data: dict):
        wm_data = data.get("_sovereign_watermark")
        if not wm_data:
            return {"valid": False, "reason": "No watermark found in document"}
        return DocumentWatermarker.verify_watermark(wm_data.get("token", ""))
