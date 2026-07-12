import hashlib
import hmac as hmac_mod
import json
import os
from pathlib import Path
from typing import Optional
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from app.config import settings
import structlog

logger = structlog.get_logger(__name__)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_event_hash(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256_hex(canonical.encode("utf-8"))


def verify_hmac(payload: bytes, signature_hex: str, secret: str) -> bool:
    expected = hmac_mod.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return hmac_mod.compare_digest(expected, signature_hex)


class KeyManager:
    def __init__(self, keys_dir: Optional[Path] = None):
        self.keys_dir = keys_dir or settings.KEYS_DIR
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self._private_key: Optional[Ed25519PrivateKey] = None
        self._public_key: Optional[Ed25519PublicKey] = None
        self._key_id: str = ""

    def initialize(self):
        priv_path = self.keys_dir / "signing_key.pem"
        pub_path = self.keys_dir / "signing_key.pub"
        if priv_path.exists():
            self._load_keys(priv_path, pub_path)
        else:
            self._generate_keys(priv_path, pub_path)
        logger.info("key_manager.initialized", key_id=self._key_id)

    def _generate_keys(self, priv_path, pub_path):
        self._private_key = Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()
        priv_bytes = self._private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        priv_path.write_bytes(priv_bytes)
        os.chmod(priv_path, 0o600)
        pub_bytes = self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pub_path.write_bytes(pub_bytes)
        self._key_id = sha256_hex(pub_bytes)[:16]

    def _load_keys(self, priv_path, pub_path):
        priv_bytes = priv_path.read_bytes()
        self._private_key = serialization.load_pem_private_key(priv_bytes, password=None)
        self._public_key = self._private_key.public_key()
        pub_bytes = pub_path.read_bytes()
        self._key_id = sha256_hex(pub_bytes)[:16]

    def sign(self, data: bytes) -> str:
        if not self._private_key:
            raise RuntimeError("KeyManager not initialized")
        return self._private_key.sign(data).hex()

    def verify(self, data: bytes, signature_hex: str) -> bool:
        if not self._public_key:
            raise RuntimeError("KeyManager not initialized")
        try:
            self._public_key.verify(bytes.fromhex(signature_hex), data)
            return True
        except InvalidSignature:
            return False

    @property
    def key_id(self) -> str:
        return self._key_id


class MerkleTree:
    def __init__(self):
        self.leaves: list[str] = []

    def add_leaf(self, leaf_hash: str) -> int:
        self.leaves.append(leaf_hash)
        return len(self.leaves) - 1

    def compute_root(self) -> str:
        if not self.leaves:
            return sha256_hex(b"empty_merkle_tree")
        level = list(self.leaves)
        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else level[i]
                combined = bytes.fromhex(left) + bytes.fromhex(right)
                next_level.append(sha256_hex(combined))
            level = next_level
        return level[0]

    def get_proof(self, leaf_index: int) -> list[dict]:
        if leaf_index >= len(self.leaves):
            raise IndexError(f"Leaf index {leaf_index} out of range")
        proof = []
        level = list(self.leaves)
        index = leaf_index
        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else level[i]
                combined = bytes.fromhex(left) + bytes.fromhex(right)
                next_level.append(sha256_hex(combined))
                if i == index or i + 1 == index:
                    if index % 2 == 0:
                        sibling = right
                        position = "right"
                    else:
                        sibling = left
                        position = "left"
                    if left != right:
                        proof.append({"hash": sibling, "position": position})
            level = next_level
            index = index // 2
        return proof

    @staticmethod
    def verify_proof(leaf_hash: str, proof: list[dict], expected_root: str) -> bool:
        current = leaf_hash
        for step in proof:
            sibling = step["hash"]
            if step["position"] == "right":
                combined = bytes.fromhex(current) + bytes.fromhex(sibling)
            else:
                combined = bytes.fromhex(sibling) + bytes.fromhex(current)
            current = sha256_hex(combined)
        return current == expected_root


key_manager = KeyManager()
