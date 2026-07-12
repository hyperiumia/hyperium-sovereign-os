use std::path::PathBuf;
use std::collections::VecDeque;
use tokio::fs;
use tracing::{info, warn};

use crate::AgentEvent;
use crate::crypto::signer::SignedEvent;

pub struct EventQueue {
    path: PathBuf,
    max_events: usize,
    in_memory: VecDeque<(AgentEvent, SignedEvent)>,
}

impl EventQueue {
    pub async fn new(path: PathBuf, max_events: usize) -> Self {
        let mut queue = Self {
            path,
            max_events,
            in_memory: VecDeque::new(),
        };
        queue.load_from_disk().await;
        queue
    }

    pub async fn enqueue(&mut self, event: AgentEvent, signed: SignedEvent) {
        if self.in_memory.len() >= self.max_events {
            self.in_memory.pop_front();
            warn!("Event queue full, dropping oldest event");
        }
        self.in_memory.push_back((event.clone(), signed.clone()));
        self.append_to_disk(&event, &signed).await;
    }

    pub fn drain(&mut self, batch_size: usize) -> Vec<(AgentEvent, SignedEvent)> {
        let drain_count = batch_size.min(self.in_memory.len());
        self.in_memory.drain(..drain_count).collect()
    }

    pub fn len(&self) -> usize {
        self.in_memory.len()
    }

    pub fn is_empty(&self) -> bool {
        self.in_memory.is_empty()
    }

    async fn append_to_disk(&self, event: &AgentEvent, signed: &SignedEvent) {
        if let Some(parent) = self.path.parent() {
            let _ = fs::create_dir_all(parent).await;
        }

        let record = serde_json::json!({
            "event": event,
            "signed": {
                "event_hash": signed.event_hash,
                "hmac_signature": signed.hmac_signature,
            }
        });

        let line = format!("{}\n", serde_json::to_string(&record).unwrap_or_default());

        use tokio::io::AsyncWriteExt;
        match tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
        {
            Ok(mut file) => {
                let _ = file.write_all(line.as_bytes()).await;
            }
            Err(e) => {
                warn!(error = %e, "Failed to write to queue file");
            }
        }
    }

    async fn load_from_disk(&mut self) {
        let content = match fs::read_to_string(&self.path).await {
            Ok(c) => c,
            Err(_) => return,
        };

        let mut count = 0;
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }

            if let Ok(record) = serde_json::from_str::<serde_json::Value>(line) {
                if let (Some(event_val), Some(signed_val)) =
                    (record.get("event"), record.get("signed"))
                {
                    let event_parsed = serde_json::from_value::<AgentEvent>(event_val.clone());
                    let hash_opt = signed_val.get("event_hash").and_then(|v| v.as_str()).map(String::from);
                    let hmac_opt = signed_val.get("hmac_signature").and_then(|v| v.as_str()).map(String::from);

                    if let (Ok(event), Some(hash), Some(hmac)) = (event_parsed, hash_opt, hmac_opt) {
                        if self.in_memory.len() < self.max_events {
                            self.in_memory.push_back((event, SignedEvent {
                                event_hash: hash,
                                hmac_signature: hmac,
                            }));
                            count += 1;
                        }
                    }
                }
            }
        }

        if count > 0 {
            info!(count = count, "Loaded queued events from disk");
        }

        self.persist_all().await;
    }

    async fn persist_all(&self) {
        if self.in_memory.is_empty() {
            let _ = fs::remove_file(&self.path).await;
            return;
        }

        let mut lines = String::new();
        for (event, signed) in &self.in_memory {
            let record = serde_json::json!({
                "event": event,
                "signed": {
                    "event_hash": signed.event_hash,
                    "hmac_signature": signed.hmac_signature,
                }
            });
            lines.push_str(&format!("{}\n", serde_json::to_string(&record).unwrap_or_default()));
        }

        if let Some(parent) = self.path.parent() {
            let _ = fs::create_dir_all(parent).await;
        }
        let _ = fs::write(&self.path, lines).await;
    }
}
