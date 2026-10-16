#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_mut)]
#![allow(unexpected_cfgs)]

mod control;
mod interface;
mod listener;
mod route;
mod toxvpn;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn main() {
    println!("Starting ToxVPN (Rust Port)...");

    // Simple command-line argument parsing
    let args: Vec<String> = std::env::args().collect();
    let mut is_server = false;
    let mut client_toxid: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        if args[i] == "--server" {
            is_server = true;
        } else if args[i] == "--id" && i + 1 < args.len() {
            client_toxid = Some(args[i + 1].clone());
            i += 1;
        }
        i += 1;
    }

    // Generate a pseudo-random last octet based on current system time
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();

    let (local_ip, role_name) = if is_server || client_toxid.is_none() {
        // Server mode: IP range 192.168.222.1 to 192.168.222.128
        let last_octet = (nanos % 128) as u8 + 1;
        (format!("192.168.222.{}", last_octet), "SERVER")
    } else {
        // Client mode: IP range 192.168.222.129 to 192.168.222.254
        let last_octet = (nanos % 126) as u8 + 129;
        (format!("192.168.222.{}", last_octet), "CLIENT")
    };

    println!("Running as [{}] with Local IP: {}", role_name, local_ip);

    if is_server || client_toxid.is_none() {
        // Mock Tox ID generation for the server to display
        let mock_toxid = "76543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA98";
        println!("--------------------------------------------------");
        println!("Server Tox ID: {}", mock_toxid);
        println!("--------------------------------------------------");
    } else {
        println!("Connecting to Server with Tox ID: {}", client_toxid.unwrap());
    }

    // Initialize system routing tables
    route::route_init();

    // Initialize the virtual network interface
    println!("Initializing virtual network interface...");
    let mut interface = interface::NetworkInterface::new(std::ptr::null_mut());
    interface.configure(&local_ip, interface::NetMode::Tun);

    // Set up graceful shutdown signal handler (Ctrl+C)
    let keep_running = Arc::new(AtomicBool::new(true));
    let r = keep_running.clone();

    if let Err(err) = ctrlc::set_handler(move || {
        println!("\nInterrupt received, shutting down gracefully...");
        r.store(false, Ordering::SeqCst);
    }) {
        eprintln!("Error setting Ctrl-C handler: {err}");
    }

    let mut toxvpn_core = toxvpn::ToxVpnCore::default();

    println!("ToxVPN is running. Press Ctrl+C to exit.");

    while keep_running.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(50));
    }

    println!("ToxVPN exited successfully.");
}
