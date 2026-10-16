use std::fs;
use std::process::Command;
use std::ffi::CString;
use crate::tox_core;

/// Fetches the latest public nodes via curl, saves to res/bootstrap.json, and bootstraps Tox
pub fn bootstrap_tox(tox_ptr: *mut std::ffi::c_void) {
    println!("[*] Fetching latest Tox bootstrap nodes...");
    
    // Ensure res directory exists
    let _ = fs::create_dir_all("res");

    // Run curl to download nodes.tox.chat/json
    let status = Command::new("curl")
        .args(["-s", "https://nodes.tox.chat/json", "-o", "res/bootstrap.json"])
        .status();

    let mut bootstrapped = false;

    if status.is_ok() && status.unwrap().success() {
        if let Ok(content) = fs::read_to_string("res/bootstrap.json") {
            if let Some(node) = parse_first_node(&content) {
                let host = CString::new(node.ipv4).unwrap();
                let pubkey_bytes = hex::decode(node.public_key).unwrap_or_default();
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

struct NodeInfo {
    ipv4: String,
    port: u16,
    public_key: String,
}

fn parse_first_node(json: &str) -> Option<NodeInfo> {
    let ipv4_idx = json.find("\"ipv4\"")?;
    let ip_start = json[ipv4_idx..].find(':')? + ipv4_idx;
    let ip_quote1 = json[ip_start..].find('"')? + ip_start;
    let ip_quote2 = json[ip_quote1 + 1..].find('"')? + ip_quote1 + 1;
    let ipv4 = json[ip_quote1 + 1..ip_quote2].to_string();

    let port_idx = json.find("\"port\"")?;
    let port_start = json[port_idx..].find(':')? + port_idx;
    let port_end = json[port_start..].find(|c: char| !c.is_numeric() && c != ' ')? + port_start;
    let port_str = json[port_start..port_end].trim();
    let port: u16 = port_str.parse().unwrap_or(33445);

    let pk_idx = json.find("\"public_key\"")?;
    let pk_start = json[pk_idx..].find(':')? + pk_idx;
    let pk_quote1 = json[pk_start..].find('"')? + pk_start;
    let pk_quote2 = json[pk_quote1 + 1..].find('"')? + pk_quote1 + 1;
    let public_key = json[pk_quote1 + 1..pk_quote2].to_string();

    Some(NodeInfo { ipv4, port, public_key })
}
