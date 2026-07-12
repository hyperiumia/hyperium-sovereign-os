use tracing::{info, warn, error};

/// Handles enforcement actions returned by the server.
/// When the server says FREEZE or ISOLATE, the agent takes
/// local action on the endpoint.
pub struct Enforcer {
    freeze_enabled: bool,
    isolate_enabled: bool,
}

impl Enforcer {
    pub fn new(freeze_enabled: bool, isolate_enabled: bool) -> Self {
        Self { freeze_enabled, isolate_enabled }
    }

    pub fn execute(&self, actions: &[String]) {
        for action in actions {
            match action.as_str() {
                "SESSION_FROZEN" => {
                    if self.freeze_enabled {
                        self.freeze_session();
                    }
                }
                "SESSION_ISOLATED" => {
                    if self.isolate_enabled {
                        self.isolate_endpoint();
                    }
                }
                "ACTION_BLOCKED" => {
                    info!("Server confirmed action was blocked");
                }
                "ALERT_CREATED" => {
                    info!("Server created security alert");
                }
                other if other.contains("FROZEN") => {
                    if self.freeze_enabled {
                        self.freeze_session();
                    }
                }
                other if other.contains("ISOLATED") => {
                    if self.isolate_enabled {
                        self.isolate_endpoint();
                    }
                }
                _ => {}
            }
        }
    }

    fn freeze_session(&self) {
        warn!("EXECUTING SESSION FREEZE — locking screen");

        // Try multiple methods to lock the screen
        let locked = try_lock_screen();

        if locked {
            info!("Session frozen successfully");
        } else {
            warn!("Could not lock screen — no display manager detected");
        }

        // Kill suspicious processes regardless
        kill_suspicious_processes();
    }

    fn isolate_endpoint(&self) {
        error!("EXECUTING NETWORK ISOLATION — dropping all outbound connections");

        // Add iptables rule to drop all outbound traffic except to our server
        let result = std::process::Command::new("iptables")
            .args(["-A", "OUTPUT", "-p", "tcp", "--dport", "8000", "-j", "ACCEPT"])
            .output();

        match result {
            Ok(_) => info!("Server connection preserved"),
            Err(e) => warn!(error = %e, "Could not configure iptables (need root)"),
        }

        let result = std::process::Command::new("iptables")
            .args(["-A", "OUTPUT", "-j", "DROP"])
            .output();

        match result {
            Ok(_) => {
                info!("All outbound traffic dropped — endpoint isolated");
                info!("Only connection to Sovereign-OS server preserved");
            }
            Err(e) => warn!(error = %e, "Could not apply isolation (need root)"),
        }
    }
}

fn try_lock_screen() -> bool {
    // Try common screen lock commands
    let lock_commands = [
        // GNOME
        vec!["gnome-screensaver-command", "--lock"],
        // KDE
        vec!["qdbus", "org.kde.screensaver", "/ScreenSaver", "Lock"],
        // Generic X11
        vec!["xdg-screensaver", "lock"],
        // systemd-based
        vec!["loginctl", "lock-session"],
    ];

    for cmd in &lock_commands {
        if let Ok(output) = std::process::Command::new(cmd[0]).args(&cmd[1..]).output() {
            if output.status.success() {
                return true;
            }
        }
    }

    false
}

fn kill_suspicious_processes() {
    // Look for common exfiltration tools
    let suspicious = ["nc", "ncat", "socat", "curl", "wget", "scp", "rsync", "rclone"];

    for proc in &suspicious {
        let _ = std::process::Command::new("pkill")
            .args(["-f", proc])
            .output();
    }
}
