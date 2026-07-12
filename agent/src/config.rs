use serde::Deserialize;
use anyhow::{Context, Result};
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct AgentConfig {
    pub agent_id: String,
    pub device_id: String,
    pub server_url: String,
    pub hmac_secret: String,
    #[serde(default = "default_watch_paths")]
    pub watch_paths: Vec<String>,
    #[serde(default = "default_usb_poll_ms")]
    pub usb_poll_ms: u64,
    #[serde(default = "default_network_poll_ms")]
    pub network_poll_ms: u64,
    #[serde(default = "default_true")]
    pub filesystem_enabled: bool,
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    #[serde(default = "default_retry_base_ms")]
    pub retry_base_ms: u64,
    #[serde(default = "default_queue_max")]
    pub queue_max_events: usize,
    #[serde(default = "default_queue_flush")]
    pub queue_flush_batch: usize,
    #[serde(default = "default_health_interval")]
    pub health_check_interval_s: u64,
    #[serde(default = "default_true")]
    pub freeze_on_high_risk: bool,
    #[serde(default = "default_true")]
    pub isolate_on_critical: bool,
}

fn default_watch_paths() -> Vec<String> { vec!["/tmp".into(), "/home".into()] }
fn default_usb_poll_ms() -> u64 { 2000 }
fn default_network_poll_ms() -> u64 { 3000 }
fn default_true() -> bool { true }
fn default_max_retries() -> u32 { 5 }
fn default_retry_base_ms() -> u64 { 1000 }
fn default_queue_max() -> usize { 10000 }
fn default_queue_flush() -> usize { 50 }
fn default_health_interval() -> u64 { 30 }

impl AgentConfig {
    pub fn load() -> Result<Self> {
        let config_path = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("sovereign-agent")
            .join("agent.toml");

        let alt_path = PathBuf::from("config/agent.toml");

        let path = if config_path.exists() {
            config_path
        } else if alt_path.exists() {
            alt_path
        } else {
            anyhow::bail!(
                "Config not found. Searched:\n  {}\n  {}",
                config_path.display(),
                alt_path.display()
            );
        };

        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config: {}", path.display()))?;

        let config: AgentConfig = toml::from_str(&contents)
            .with_context(|| format!("Failed to parse config: {}", path.display()))?;

        Ok(config)
    }

    pub fn queue_path(&self) -> PathBuf {
        dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("sovereign-agent")
            .join("event_queue.jsonl")
    }
}
