use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, debug};
use anyhow::Result;

use crate::AgentEvent;
use crate::crypto::signer::SignedEvent;

#[derive(Debug, Serialize)]
struct ServerEvent {
    agent_id: String,
    device_id: String,
    session_id: Option<String>,
    event_type: String,
    source_module: String,
    payload: serde_json::Value,
    severity: String,
    timestamp: String,
    event_hash: String,
    hmac_signature: String,
}

#[derive(Debug, Deserialize)]
pub struct ServerResponse {
    pub status: String,
    pub event_id: String,
    pub merkle_epoch: Option<i64>,
    pub actions_taken: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub signing_key_id: String,
}

pub struct ServerClient {
    client: Client,
    server_url: String,
    agent_id: String,
    device_id: String,
}

impl ServerClient {
    pub fn new(server_url: &str, agent_id: &str, device_id: &str) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()?;

        Ok(Self {
            client,
            server_url: server_url.trim_end_matches('/').to_string(),
            agent_id: agent_id.to_string(),
            device_id: device_id.to_string(),
        })
    }

    pub async fn send_event(
        &self,
        event: &AgentEvent,
        signed: &SignedEvent,
    ) -> Result<ServerResponse> {
        let server_event = ServerEvent {
            agent_id: self.agent_id.clone(),
            device_id: self.device_id.clone(),
            session_id: None,
            event_type: event.event_type.clone(),
            source_module: event.source_module.clone(),
            payload: event.payload.clone(),
            severity: event.severity.clone(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            event_hash: signed.event_hash.clone(),
            hmac_signature: signed.hmac_signature.clone(),
        };

        let url = format!("{}/api/v1/events/ingest", self.server_url);

        let response = self
            .client
            .post(&url)
            .json(&server_event)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Server returned {}: {}", status, body);
        }

        let result: ServerResponse = response.json().await?;
        Ok(result)
    }

    pub async fn send_batch(
        &self,
        events: &[(AgentEvent, SignedEvent)],
    ) -> Result<Vec<ServerResponse>> {
        let server_events: Vec<ServerEvent> = events.iter().map(|(event, signed)| {
            ServerEvent {
                agent_id: self.agent_id.clone(),
                device_id: self.device_id.clone(),
                session_id: None,
                event_type: event.event_type.clone(),
                source_module: event.source_module.clone(),
                payload: event.payload.clone(),
                severity: event.severity.clone(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                event_hash: signed.event_hash.clone(),
                hmac_signature: signed.hmac_signature.clone(),
            }
        }).collect();

        let url = format!("{}/api/v1/events/ingest/batch", self.server_url);

        let response = self
            .client
            .post(&url)
            .json(&serde_json::json!({ "events": server_events }))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Batch send failed {}: {}", status, body);
        }

        let result: serde_json::Value = response.json().await?;
        let results = result.get("results")
            .and_then(|r| serde_json::from_value(r.clone()).ok())
            .unwrap_or_default();

        Ok(results)
    }

    pub async fn health_check(&self) -> Result<HealthResponse> {
        let url = format!("{}/health", self.server_url);
        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            anyhow::bail!("Health check failed: {}", response.status());
        }

        let result: HealthResponse = response.json().await?;
        Ok(result)
    }
}
