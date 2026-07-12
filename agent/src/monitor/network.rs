use std::collections::HashSet;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{info, debug};

use crate::AgentEvent;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct Connection {
    local_addr: String,
    local_port: u16,
    remote_addr: String,
    remote_port: u16,
    state: String,
}

pub struct NetworkMonitor {
    device_id: String,
    poll_interval: Duration,
    known: HashSet<String>,
}

impl NetworkMonitor {
    pub fn new(device_id: String, poll_interval_ms: u64) -> Self {
        Self {
            device_id,
            poll_interval: Duration::from_millis(poll_interval_ms),
            known: HashSet::new(),
        }
    }

    pub async fn run(&mut self, tx: mpsc::Sender<AgentEvent>) -> Result<(), anyhow::Error> {
        info!("Network monitor started (polling every {}ms)", self.poll_interval.as_millis());

        loop {
            sleep(self.poll_interval).await;

            let connections = read_tcp_connections();

            for conn in &connections {
                let key = format!("{}:{}->{}:{}", conn.local_addr, conn.local_port, conn.remote_addr, conn.remote_port);

                if !self.known.contains(&key) && !is_internal(&conn.remote_addr) {
                    self.known.insert(key);

                    debug!(remote = %conn.remote_addr, port = conn.remote_port, "New external connection");

                    let event = AgentEvent {
                        event_type: "network.connection.new".to_string(),
                        source_module: "network_monitor".to_string(),
                        payload: serde_json::json!({
                            "local_addr": conn.local_addr,
                            "local_port": conn.local_port,
                            "remote_addr": conn.remote_addr,
                            "remote_port": conn.remote_port,
                            "state": conn.state,
                            "host_device": self.device_id,
                            "whitelisted": false,
                            "data_bytes": 0,
                        }),
                        severity: classify_severity(conn.remote_port).to_string(),
                    };

                    if tx.send(event).await.is_err() {
                        return Ok(());
                    }
                }
            }

            // Cleanup stale connections
            let current_keys: HashSet<String> = connections.iter()
                .map(|c| format!("{}:{}->{}:{}", c.local_addr, c.local_port, c.remote_addr, c.remote_port))
                .collect();
            self.known.retain(|k| current_keys.contains(k));
        }
    }
}

fn read_tcp_connections() -> Vec<Connection> {
    let mut connections = Vec::new();

    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 {
                continue;
            }

            let local = parse_address(fields[1]);
            let remote = parse_address(fields[2]);
            let state = fields[3];

            if let (Some((la, lp)), Some((ra, rp))) = (local, remote) {
                connections.push(Connection {
                    local_addr: la,
                    local_port: lp,
                    remote_addr: ra,
                    remote_port: rp,
                    state: state.to_string(),
                });
            }
        }
    }

    connections
}

fn parse_address(hex_addr: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = hex_addr.split(':').collect();
    if parts.len() != 2 {
        return None;
    }

    let port = u16::from_str_radix(parts[1], 16).ok()?;
    let ip_hex = parts[0];

    if ip_hex.len() == 8 {
        let bytes = u32::from_str_radix(ip_hex, 16).ok()?;
        let addr = format!(
            "{}.{}.{}.{}",
            bytes & 0xFF,
            (bytes >> 8) & 0xFF,
            (bytes >> 16) & 0xFF,
            (bytes >> 24) & 0xFF
        );
        Some((addr, port))
    } else {
        None // Skip IPv6 for MVP
    }
}

fn is_internal(addr: &str) -> bool {
    addr.starts_with("127.")
        || addr.starts_with("10.")
        || addr.starts_with("192.168.")
        || addr.starts_with("172.16.")
        || addr.starts_with("172.17.")
        || addr.starts_with("172.18.")
        || addr.starts_with("172.19.")
        || addr.starts_with("172.2")
        || addr.starts_with("172.3")
        || addr == "0.0.0.0"
        || addr == "::1"
}

fn classify_severity(port: u16) -> &'static str {
    match port {
        443 | 80 => "LOW",
        22 | 3389 => "MEDIUM",    // SSH / RDP
        4444 | 5555 | 8443 => "HIGH",  // Common C2 ports
        21 | 23 | 25 => "MEDIUM", // FTP, Telnet, SMTP
        _ => "LOW",
    }
}
