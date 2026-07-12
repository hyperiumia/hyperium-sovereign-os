use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{info, debug};

use crate::AgentEvent;

pub struct SessionMonitor {
    device_id: String,
}

impl SessionMonitor {
    pub fn new(device_id: String) -> Self {
        Self { device_id }
    }

    pub async fn run(&self, tx: mpsc::Sender<AgentEvent>) -> Result<(), anyhow::Error> {
        info!("Session monitor started");

        let mut last_user = String::new();

        loop {
            sleep(Duration::from_secs(10)).await;

            // Read current logged-in user from /var/run/utmp or `who`
            let current_user = get_active_user();

            if current_user != last_user && !current_user.is_empty() {
                info!(user = %current_user, "Session change detected");

                let event = AgentEvent {
                    event_type: "session.change".to_string(),
                    source_module: "session_monitor".to_string(),
                    payload: serde_json::json!({
                        "user": current_user,
                        "previous_user": last_user,
                        "host_device": self.device_id,
                        "action": if last_user.is_empty() { "login" } else { "user_switch" },
                    }),
                    severity: "LOW".to_string(),
                };

                if tx.send(event).await.is_err() {
                    return Ok(());
                }

                last_user = current_user;
            }
        }
    }
}

fn get_active_user() -> String {
    // Try `who` command first
    if let Ok(output) = std::process::Command::new("who").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if !fields.is_empty() {
                return fields[0].to_string();
            }
        }
    }

    // Fallback: read LOGNAME or USER env
    std::env::var("LOGNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_default()
}
