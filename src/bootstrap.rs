use std::fs;
use std::process::Command;
use std::ffi::CString;
use serde::Deserialize;
use crate::tox_core;

#[derive(Debug, Deserialize)]
struct NodeInfo {
    ipv4: String,
    port: u16,
    public_key: String,
}

/// Fetches the latest public nodes via curl, saves to res/bootstrap.json, and bootstraps Tox
pub fn bootstrap_tox(tox_ptr: *mut std::ffi::c_void) {
    println!("[*] Fetching latest Tox bootstrap nodes...");
    
    let _ = fs::create_dir_all("res");

    let status = Command::new("curl")
        .args(["-s", "https://nodes.tox.chat/json", "-o", "res/bootstrap.json"])
        .status();

    let mut bootstrapped = false;

    if status.is_ok() && status.unwrap().success() {
        if let Ok(content) = fs::read_to_string("res/bootstrap.json") {
            if let Ok(nodes) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(node_array) = nodes.get("nodes").and_then(|n| n.as_array()) {
                    if let Some(first_node_val) = node_array.first() {
                        if let Ok(node) = serde_json::from_value::<NodeInfo>(first_node_val.clone()) {
                            if let Ok(host) = CString::new(node.ipv4) {
                                let pubkey_bytes = hex::decode(&node.public_key).unwrap_or_default();
                                if pubkey_bytes.len() == 32 {
                                    let mut err = 0;
                                    let success = unsafe {
                                        tox_core::tox_bootstrap(
                                            tox_ptr,
                                            host.as_ptr(),
                                            node.port,
                                            pubkey_bytes.as_ptr(),
                                            &mut err,
                                        )
                                    };
                                    if success {
                                        println!("[+] Successfully bootstrapped using node from res/bootstrap.json!");
                                        bootstrapped = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Fallback if download or parsing fails
    if !bootstrapped {
        println!("[-] Falling back to hardcoded bootstrap node...");
        let host = CString::new("198.98.51.198").unwrap();
        let port = 33445;
        let pubkey_hex = "1C5299444458BAA7627F839A2500D0090D4D2024EDF2E80562D5A64C0BA56952";
        let pubkey_bytes = hex::decode(pubkey_hex).unwrap();
        let mut err = 0;
        let success = unsafe {
            tox_core::tox_bootstrap(
                tox_ptr,
                host.as_ptr(),
                port,
                pubkey_bytes.as_ptr(),
                &mut err,
            )
        };
        if success {
            println!("[+] Successfully bootstrapped using fallback node!");
        } else {
            eprintln!("[-] Fallback bootstrap failed with error code: {err}");
        }
    }
}

pub fn get_public_ip() -> String {
    let output = Command::new("curl")
        .args(["-s", "https://api.ipify.org"])
        .output();

    if let Ok(res) = output {
        if res.status.success() {
            let ip = String::from_utf8_lossy(&res.stdout).trim().to_string();
            if !ip.is_empty() {
                return ip;
            }
        }
    }

    let fallback = Command::new("curl")
        .args(["-s", "https://icanhazip.com"])
        .output();

    if let Ok(res) = fallback {
        if res.status.success() {
            let ip = String::from_utf8_lossy(&res.stdout).trim().to_string();
            if !ip.is_empty() {
                return ip;
            }
        }
    }

    "127.0.0.1 (Local/NAT)".to_string()
}
