use std::os::unix::io::AsRawFd;
use std::path::Path;
use inotify::{Inotify, WatchMask};
use tokio::sync::mpsc;
use tokio::task;
use tracing::{info, warn};

use crate::AgentEvent;

pub struct FilesystemMonitor {
    watch_paths: Vec<String>,
}

impl FilesystemMonitor {
    pub fn new(watch_paths: Vec<String>) -> Self {
        Self { watch_paths }
    }

    pub async fn run(&self, tx: mpsc::Sender<AgentEvent>) -> Result<(), anyhow::Error> {
        let mut inotify = Inotify::init()?;

        let mask = WatchMask::CREATE
            | WatchMask::MODIFY
            | WatchMask::DELETE
            | WatchMask::MOVED_FROM
            | WatchMask::MOVED_TO;

        for path_str in &self.watch_paths {
            let path = Path::new(path_str);
            if !path.exists() {
                warn!(path = %path_str, "Watch path does not exist, skipping");
                continue;
            }

            match inotify.watches().add(path, mask) {
                Ok(_) => info!(path = %path_str, "Filesystem watch active"),
                Err(e) => warn!(path = %path_str, error = %e, "Failed to watch path"),
            }
        }

        // Set fd to non-blocking via libc
        let fd = inotify.as_raw_fd();
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }

        info!("Filesystem monitor started (non-blocking fd={})", fd);

        // Run blocking poll loop in a dedicated OS thread
        let handle = task::spawn_blocking(move || {
            blocking_inotify_loop(inotify, tx)
        });

        handle.await??;
        Ok(())
    }
}

fn blocking_inotify_loop(
    mut inotify: Inotify,
    tx: mpsc::Sender<AgentEvent>,
) -> Result<(), anyhow::Error> {
    let mut buffer = [0u8; 4096];

    loop {
        match inotify.read_events(&mut buffer) {
            Ok(events) => {
                for event in events {
                    let name = event
                        .name
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();

                    if name.is_empty() {
                        continue;
                    }

                    // Skip temp and hidden files
                    if name.starts_with('.') || name.ends_with('~') || name.ends_with(".swp") {
                        continue;
                    }

                    let mut event_type = "filesystem.change".to_string();
                    let mut severity = "LOW".to_string();

                    if event.mask.contains(inotify::EventMask::CREATE) {
                        event_type = "filesystem.file_created".to_string();
                    }
                    if event.mask.contains(inotify::EventMask::DELETE) {
                        event_type = "filesystem.file_deleted".to_string();
                        severity = "MEDIUM".to_string();
                    }
                    if event.mask.contains(inotify::EventMask::MOVED_FROM) {
                        event_type = "filesystem.file_moved_out".to_string();
                        severity = "MEDIUM".to_string();
                    }

                    let name_lower = name.to_lowercase();

                    // Detect log deletion
                    if (name_lower.contains("log") || name_lower.contains("audit")
                        || name_lower.contains("auth") || name_lower.contains("syslog"))
                        && event.mask.contains(inotify::EventMask::DELETE)
                    {
                        event_type = "filesystem.log_deletion_attempt".to_string();
                        severity = "CRITICAL".to_string();
                    }

                    // Detect ransomware
                    if name_lower.ends_with(".locked")
                        || name_lower.ends_with(".encrypted")
                        || name_lower.ends_with(".crypto")
                        || name_lower == "readme.txt"
                        || name_lower == "how_to_decrypt.txt"
                    {
                        event_type = "filesystem.mass_encrypt".to_string();
                        severity = "CRITICAL".to_string();
                    }

                    let agent_event = AgentEvent {
                        event_type,
                        source_module: "filesystem_monitor".to_string(),
                        payload: serde_json::json!({
                            "filename": name,
                            "watch_mask": format!("{:?}", event.mask),
                            "timestamp": chrono::Utc::now().to_rfc3339(),
                        }),
                        severity,
                    };

                    if tx.blocking_send(agent_event).is_err() {
                        return Ok(());
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No events, sleep to avoid busy-wait
                std::thread::sleep(std::time::Duration::from_millis(200));
                continue;
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }
}
