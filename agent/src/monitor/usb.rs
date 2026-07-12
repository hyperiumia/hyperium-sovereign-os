use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{info, warn, debug};

use crate::AgentEvent;

const STORAGE_VENDORS: &[&str] = &[
    "0781", // SanDisk
    "0951", // Kingston
    "090c", // Silicon Motion
    "154b", // PNY
    "058f", // Alcor Micro
    "0930", // Toshiba
    "04e8", // Samsung
    "1f75", // Innostor
];

pub struct UsbMonitor {
    device_id: String,
    poll_interval: Duration,
}

#[derive(Debug, Clone)]
struct UsbDevice {
    vendor_id: String,
    product_id: String,
    vendor_name: String,
    device_type: String,
}

impl UsbMonitor {
    pub fn new(device_id: String, poll_interval_ms: u64) -> Self {
        Self {
            device_id,
            poll_interval: Duration::from_millis(poll_interval_ms),
        }
    }

    pub async fn run(&self, tx: mpsc::Sender<AgentEvent>) -> Result<(), anyhow::Error> {
        info!("USB monitor started (polling every {}ms)", self.poll_interval.as_millis());

        let mut known: HashMap<String, UsbDevice> = HashMap::new();

        // Initial scan
        Self::scan(&mut known);

        loop {
            sleep(self.poll_interval).await;

            let mut current: HashMap<String, UsbDevice> = HashMap::new();
            Self::scan(&mut current);

            // New devices
            for (key, device) in &current {
                if !known.contains_key(key) {
                    info!(device = %key, vendor = %device.vendor_name, "USB connected");

                    let event = AgentEvent {
                        event_type: "usb.device.connected".to_string(),
                        source_module: "usb_monitor".to_string(),
                        payload: serde_json::json!({
                            "vendor_id": device.vendor_id,
                            "product_id": device.product_id,
                            "vendor_name": device.vendor_name,
                            "device_type": device.device_type,
                            "host_device": self.device_id,
                        }),
                        severity: if device.device_type == "storage" { "HIGH" } else { "MEDIUM" }.to_string(),
                    };

                    if tx.send(event).await.is_err() {
                        return Ok(());
                    }
                }
            }

            // Removed devices
            for key in known.keys() {
                if !current.contains_key(key) {
                    info!(device = %key, "USB disconnected");
                    let event = AgentEvent {
                        event_type: "usb.device.disconnected".to_string(),
                        source_module: "usb_monitor".to_string(),
                        payload: serde_json::json!({
                            "device_id": key,
                            "host_device": self.device_id,
                        }),
                        severity: "LOW".to_string(),
                    };
                    let _ = tx.send(event).await;
                }
            }

            known = current;
        }
    }

    fn scan(devices: &mut HashMap<String, UsbDevice>) {
        let usb_path = Path::new("/sys/bus/usb/devices");
        if !usb_path.exists() {
            return;
        }

        let entries = match std::fs::read_dir(usb_path) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            // Skip interfaces (contain ":") and root hub
            if name.contains(':') || name == "usb" {
                continue;
            }

            let vendor = std::fs::read_to_string(entry.path().join("idVendor"))
                .unwrap_or_default()
                .trim()
                .to_string();
            let product = std::fs::read_to_string(entry.path().join("idProduct"))
                .unwrap_or_default()
                .trim()
                .to_string();

            if vendor.is_empty() {
                continue;
            }

            let key = format!("{}:{}", vendor, product);

            // Try to read manufacturer string
            let manufacturer = std::fs::read_to_string(entry.path().join("manufacturer"))
                .unwrap_or_else(|_| "Unknown".to_string())
                .trim()
                .to_string();

            let device_class = std::fs::read_to_string(entry.path().join("bDeviceClass"))
                .unwrap_or_default()
                .trim()
                .to_string();

            let device_type = classify_device(&vendor, &device_class);

            devices.insert(key, UsbDevice {
                vendor_id: vendor,
                product_id: product,
                vendor_name: manufacturer,
                device_type: device_type.to_string(),
            });
        }
    }
}

fn classify_device(vendor_id: &str, device_class: &str) -> &'static str {
    // Class 08 = Mass Storage
    if device_class == "08" {
        return "storage";
    }
    // Known storage vendors
    if STORAGE_VENDORS.contains(&vendor_id) {
        return "storage";
    }
    // Class 03 = HID (keyboard, mouse)
    if device_class == "03" {
        return "hid";
    }
    // Class 02 = Communications (network adapters, modems)
    if device_class == "02" || device_class == "0a" {
        return "network";
    }
    "unknown"
}
