use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use serde_json::Value;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct SignedEvent {
    pub event_hash: String,
    pub hmac_signature: String,
}

pub struct EventSigner {
    secret: Vec<u8>,
}

impl EventSigner {
    pub fn new(secret: &str) -> Self {
        Self {
            secret: secret.as_bytes().to_vec(),
        }
    }

    pub fn sign_payload(&self, payload: &Value) -> SignedEvent {
        // Canonical JSON: sorted keys, no spaces
        let canonical = serde_json::to_string(payload)
            .unwrap_or_else(|_| "{}".to_string());

        // SHA-256 hash of payload
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        let hash = hasher.finalize();
        let event_hash = hex::encode(hash);

        // HMAC-SHA256 of payload
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .expect("HMAC accepts any key length");
        mac.update(canonical.as_bytes());
        let hmac_result = mac.finalize();
        let hmac_signature = hex::encode(hmac_result.into_bytes());

        SignedEvent {
            event_hash,
            hmac_signature,
        }
    }

    pub fn verify_payload(&self, payload: &Value, expected_hash: &str, expected_hmac: &str) -> bool {
        let signed = self.sign_payload(payload);
        signed.event_hash == expected_hash && signed.hmac_signature == expected_hmac
    }
}
