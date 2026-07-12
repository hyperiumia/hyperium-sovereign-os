"""
Tests para el core criptográfico:
- SHA-256 hashing
- HMAC-SHA256 verification
- Merkle Tree construction, root computation, proofs
- Ed25519 signing and verification
- KeyManager lifecycle
"""
import pytest
from app.core.crypto import (
    sha256_hex,
    compute_event_hash,
    verify_hmac,
    MerkleTree,
    KeyManager,
)


class TestHashing:
    def test_sha256_deterministic(self):
        data = b"hello world"
        h1 = sha256_hex(data)
        h2 = sha256_hex(data)
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 = 32 bytes = 64 hex chars

    def test_sha256_different_inputs(self):
        h1 = sha256_hex(b"hello")
        h2 = sha256_hex(b"world")
        assert h1 != h2

    def test_compute_event_hash_deterministic(self):
        payload = {"action": "usb.connected", "device": "sdb1"}
        h1 = compute_event_hash(payload)
        h2 = compute_event_hash(payload)
        assert h1 == h2
        assert len(h1) == 64

    def test_compute_event_hash_key_order_independent(self):
        """El hash debe ser igual sin importar el orden de las claves."""
        p1 = {"a": 1, "b": 2, "c": 3}
        p2 = {"c": 3, "a": 1, "b": 2}
        assert compute_event_hash(p1) == compute_event_hash(p2)

    def test_compute_event_hash_different_payloads(self):
        h1 = compute_event_hash({"action": "read"})
        h2 = compute_event_hash({"action": "write"})
        assert h1 != h2


class TestHMAC:
    def test_hmac_verification_success(self):
        secret = "test-secret-key"
        payload = b'{"action":"test"}'
        import hmac as hmac_mod
        import hashlib
        sig = hmac_mod.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        assert verify_hmac(payload, sig, secret) is True

    def test_hmac_verification_wrong_secret(self):
        payload = b'{"action":"test"}'
        import hmac as hmac_mod
        import hashlib
        sig = hmac_mod.new(b"correct-secret", payload, hashlib.sha256).hexdigest()
        assert verify_hmac(payload, sig, "wrong-secret") is False

    def test_hmac_verification_tampered_payload(self):
        secret = "test-secret"
        import hmac as hmac_mod
        import hashlib
        original = b'{"action":"test"}'
        sig = hmac_mod.new(secret.encode(), original, hashlib.sha256).hexdigest()
        tampered = b'{"action":"hacked"}'
        assert verify_hmac(tampered, sig, secret) is False


class TestMerkleTree:
    def test_empty_tree_root(self):
        tree = MerkleTree()
        root = tree.compute_root()
        assert len(root) == 64

    def test_single_leaf(self):
        tree = MerkleTree()
        tree.add_leaf(sha256_hex(b"event1"))
        root = tree.compute_root()
        assert len(root) == 64

    def test_two_leaves(self):
        tree = MerkleTree()
        h1 = sha256_hex(b"event1")
        h2 = sha256_hex(b"event2")
        tree.add_leaf(h1)
        tree.add_leaf(h2)
        root = tree.compute_root()
        # Root should be SHA-256(h1 || h2)
        expected = sha256_bytes = sha256_hex(bytes.fromhex(h1) + bytes.fromhex(h2))
        assert root == expected

    def test_odd_number_of_leaves(self):
        tree = MerkleTree()
        for i in range(3):
            tree.add_leaf(sha256_hex(f"event{i}".encode()))
        root = tree.compute_root()
        assert len(root) == 64

    def test_many_leaves_deterministic(self):
        tree1 = MerkleTree()
        tree2 = MerkleTree()
        for i in range(100):
            h = sha256_hex(f"event-{i}".encode())
            tree1.add_leaf(h)
            tree2.add_leaf(h)
        assert tree1.compute_root() == tree2.compute_root()

    def test_different_order_different_root(self):
        tree1 = MerkleTree()
        tree2 = MerkleTree()
        tree1.add_leaf(sha256_hex(b"a"))
        tree1.add_leaf(sha256_hex(b"b"))
        tree2.add_leaf(sha256_hex(b"b"))
        tree2.add_leaf(sha256_hex(b"a"))
        assert tree1.compute_root() != tree2.compute_root()

    def test_proof_generation_and_verification(self):
        tree = MerkleTree()
        hashes = [sha256_hex(f"event-{i}".encode()) for i in range(8)]
        for h in hashes:
            tree.add_leaf(h)

        root = tree.compute_root()

        # Prove inclusion of leaf 3
        proof = tree.get_proof(3)
        assert len(proof) > 0
        assert MerkleTree.verify_proof(hashes[3], proof, root) is True

        # Wrong leaf should fail
        wrong_hash = sha256_hex(b"not-in-tree")
        assert MerkleTree.verify_proof(wrong_hash, proof, root) is False

    def test_proof_all_leaves(self):
        tree = MerkleTree()
        hashes = [sha256_hex(f"evt-{i}".encode()) for i in range(16)]
        for h in hashes:
            tree.add_leaf(h)
        root = tree.compute_root()

        for i in range(16):
            proof = tree.get_proof(i)
            assert MerkleTree.verify_proof(hashes[i], proof, root) is True

    def test_proof_out_of_range(self):
        tree = MerkleTree()
        tree.add_leaf(sha256_hex(b"only-one"))
        with pytest.raises(IndexError):
            tree.get_proof(5)


class TestKeyManager:
    def test_generate_and_sign(self, tmp_path):
        km = KeyManager(keys_dir=tmp_path)
        km.initialize()

        data = b"test data to sign"
        signature = km.sign(data)
        assert len(signature) > 0
        assert km.verify(data, signature) is True

    def test_verify_wrong_data(self, tmp_path):
        km = KeyManager(keys_dir=tmp_path)
        km.initialize()

        sig = km.sign(b"original")
        assert km.verify(b"tampered", sig) is False

    def test_key_persistence(self, tmp_path):
        km1 = KeyManager(keys_dir=tmp_path)
        km1.initialize()
        key_id_1 = km1.key_id

        km2 = KeyManager(keys_dir=tmp_path)
        km2.initialize()
        key_id_2 = km2.key_id

        # Same key files = same key_id
        assert key_id_1 == key_id_2

    def test_key_id_format(self, tmp_path):
        km = KeyManager(keys_dir=tmp_path)
        km.initialize()
        assert len(km.key_id) == 16
