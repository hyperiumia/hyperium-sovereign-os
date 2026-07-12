//! Hyperium Sovereign-OS — Endpoint Agent
//!
//! Monitorea USB, red, filesystem y sesiones.
//! Reporta eventos al servidor con HMAC-SHA256.
//! Ejecuta acciones de enforcement localmente.

mod config;
mod crypto;
mod monitor;
mod comms;
mod actions;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use tracing::{info, warn, error};
use tracing_subscriber::{fmt, EnvFilter};

use config::AgentConfig;
use crypto::signer::EventSigner;
use monitor::usb::UsbMonitor;
use monitor::network::NetworkMonitor;
use monitor::filesystem::FilesystemMonitor;
use monitor::session::SessionMonitor;
use comms::server::ServerClient;
use comms::queue::EventQueue;
use actions::enforcement::Enforcer;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEvent {
    pub event_type: String,
    pub source_module: String,
    pub payload: serde_json::Value,
    pub severity: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Structured JSON logging for production
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    info!("========================================");
    info!("  Hyperium Sovereign-OS Agent v0.1.0");
    info!("========================================");

    // Load configuration
    let config = AgentConfig::load()?;
    info!(
        agent_id = %config.agent_id,
        device_id = %config.device_id,
        server = %config.server_url,
        "Configuration loaded"
    );

    // Initialize components
    let signer = EventSigner::new(&config.hmac_secret);
    let server = ServerClient::new(
        &config.server_url,
        &config.agent_id,
        &config.device_id,
    )?;
    let enforcer = Enforcer::new(config.freeze_on_high_risk, config.isolate_on_critical);
    let mut queue = EventQueue::new(config.queue_path(), config.queue_max_events).await;

    // Health check
    match server.health_check().await {
        Ok(health) => {
            info!(
                server_version = %health.version,
                signing_key = %health.signing_key_id,
                "Server connection established"
            );
        }
        Err(e) => {
            warn!(error = %e, "Server unreachable — operating in offline mode");
        }
    }

    // Channel: all monitors → central processor
    let (tx, mut rx) = mpsc::channel::<AgentEvent>(2048);

    // Spawn monitors
    let usb_tx = tx.clone();
    let usb_device_id = config.device_id.clone();
    let usb_poll = config.usb_poll_ms;
    tokio::spawn(async move {
        let monitor = UsbMonitor::new(usb_device_id, usb_poll);
        if let Err(e) = monitor.run(usb_tx).await {
            error!(error = %e, "USB monitor crashed");
        }
    });

    let net_tx = tx.clone();
    let net_device_id = config.device_id.clone();
    let net_poll = config.network_poll_ms;
    tokio::spawn(async move {
        let mut monitor = NetworkMonitor::new(net_device_id, net_poll);
        if let Err(e) = monitor.run(net_tx).await {
            error!(error = %e, "Network monitor crashed");
        }
    });

    if config.filesystem_enabled {
        let fs_tx = tx.clone();
        let fs_paths = config.watch_paths.clone();
        tokio::spawn(async move {
            let monitor = FilesystemMonitor::new(fs_paths);
            if let Err(e) = monitor.run(fs_tx).await {
                error!(error = %e, "Filesystem monitor crashed");
            }
        });
    }

    let sess_tx = tx.clone();
    let sess_device_id = config.device_id.clone();
    tokio::spawn(async move {
        let monitor = SessionMonitor::new(sess_device_id);
        if let Err(e) = monitor.run(sess_tx).await {
            error!(error = %e, "Session monitor crashed");
        }
    });

    // Drop original sender
    drop(tx);

    // Spawn queue flusher (sends queued events when server is reachable)
    let flush_server = ServerClient::new(
        &config.server_url,
        &config.agent_id,
        &config.device_id,
    )?;
    let _flush_signer = EventSigner::new(&config.hmac_secret);
    let flush_batch_size = config.queue_flush_batch;
    let flush_interval = Duration::from_secs(30);
    let flush_queue_path = config.queue_path();
    let flush_max = config.queue_max_events;
    let _flush_secret = config.hmac_secret.clone();

    tokio::spawn(async move {
        let mut flush_queue = EventQueue::new(flush_queue_path, flush_max).await;
        loop {
            sleep(flush_interval).await;

            if flush_queue.is_empty() {
                continue;
            }

            let batch = flush_queue.drain(flush_batch_size);
            if batch.is_empty() {
                continue;
            }

            info!(count = batch.len(), "Flushing queued events to server");

            match flush_server.send_batch(&batch).await {
                Ok(_) => {
                    info!(count = batch.len(), "Queue flushed successfully");
                }
                Err(e) => {
                    warn!(error = %e, "Flush failed, re-queuing events");
                    // Re-queue failed events
                    for (event, signed) in batch {
                        flush_queue.enqueue(event, signed).await;
                    }
                }
            }
        }
    });

    // Spawn periodic health check
    let hc_server = ServerClient::new(
        &config.server_url,
        &config.agent_id,
        &config.device_id,
    )?;
    let hc_interval = Duration::from_secs(config.health_check_interval_s);
    tokio::spawn(async move {
        loop {
            sleep(hc_interval).await;
            match hc_server.health_check().await {
                Ok(h) => {
                    info!(version = %h.version, key = %h.signing_key_id, "Health check OK");
                }
                Err(e) => {
                    warn!(error = %e, "Health check failed");
                }
            }
        }
    });

    // ── Central event processor ──────────────────────
    info!("All monitors active. Processing events...");

    let mut event_count: u64 = 0;
    let mut consecutive_failures: u32 = 0;

    while let Some(event) = rx.recv().await {
        event_count += 1;

        // Sign the event
        let signed = signer.sign_payload(&event.payload);

        // Try to send to server
        match server.send_event(&event, &signed).await {
            Ok(response) => {
                consecutive_failures = 0;

                info!(
                    event_type = %event.event_type,
                    event_id = %response.event_id,
                    severity = %event.severity,
                    actions = ?response.actions_taken,
                    epoch = ?response.merkle_epoch,
                    "Event processed"
                );

                // Execute enforcement actions
                if !response.actions_taken.is_empty() {
                    warn!(actions = ?response.actions_taken, "Server ordered enforcement");
                    enforcer.execute(&response.actions_taken);
                }
            }
            Err(e) => {
                consecutive_failures += 1;

                if consecutive_failures == 1 {
                    warn!(error = %e, "Server unreachable, queuing events");
                }

                // Queue event for later delivery
                queue.enqueue(event.clone(), signed.clone()).await;

                if consecutive_failures <= 3 || consecutive_failures % 100 == 0 {
                    warn!(
                        failures = consecutive_failures,
                        queue_size = queue.len(),
                        "Operating offline"
                    );
                }

                // Exponential backoff on repeated failures
                if consecutive_failures > 5 {
                    let backoff_ms = config.retry_base_ms * 2u64.pow(consecutive_failures.min(10));
                    sleep(Duration::from_millis(backoff_ms.min(30000))).await;
                }
            }
        }
    }

    info!(total_events = event_count, "Agent shutting down");
    info!("Queued events persisted to disk for next startup");
    Ok(())
}
