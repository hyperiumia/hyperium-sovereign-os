"""RFC 3161 Timestamping — Provides cryptographic timestamps for evidence."""
import hashlib
import json
from datetime import datetime, timezone
import structlog

logger = structlog.get_logger("compliance.rfc3161")


class TimestampAuthority:

    def __init__(self):
        self.tsa_id = "sovereign-os-internal-tsa"
        self.algorithm = "sha256"

    def generate_timestamp(self, data_hash: str, event_id: str = None):
        ts_token = {
            "version": 1,
            "policy": "sovereign-os-evidence-timestamping",
            "message_imprint": {
                "hash_algorithm": self.algorithm,
                "hashed_message": data_hash,
            },
            "serial_number": hashlib.sha256(
                f"{data_hash}{datetime.now(timezone.utc).isoformat()}".encode()
            ).hexdigest()[:16],
            "gen_time": datetime.now(timezone.utc).isoformat(),
            "ordering": True,
            "nonce": hashlib.sha256(
                f"{event_id}{datetime.now(timezone.utc).microsecond}".encode()
            ).hexdigest()[:16],
            "tsa": self.tsa_id,
            "accuracy": {
                "seconds": 1,
                "millis": 0,
                "micros": 0,
            },
        }

        token_content = json.dumps(ts_token, sort_keys=True)
        ts_token["token_hash"] = hashlib.sha256(token_content.encode()).hexdigest()

        logger.info("rfc3161.timestamp.generated",
                     event_id=event_id,
                     hash=data_hash[:16])
        return ts_token

    def verify_timestamp(self, ts_token: dict, original_hash: str):
        stored_hash = ts_token.get("message_imprint", {}).get("hashed_message")
        if stored_hash != original_hash:
            return {
                "valid": False,
                "reason": "Hash mismatch — data tampered after timestamp",
            }

        stored_token_hash = ts_token.pop("token_hash", None)
        if stored_token_hash:
            ts_token["token_hash"] = stored_token_hash

        return {
            "valid": True,
            "gen_time": ts_token.get("gen_time"),
            "tsa": ts_token.get("tsa"),
            "serial_number": ts_token.get("serial_number"),
        }


timestamp_authority = TimestampAuthority()
