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
use std::time::Duration;

fn main() {
    println!("Starting ToxVPN (Rust Port)...");

    // Initialize system routing tables (Linux netlink / stubs)
    route::route_init();

    // Initialize the virtual network interface (creates tox_master0 TUN device)
    println!("Initializing virtual network interface...");
    let mut interface = interface::NetworkInterface::new(std::ptr::null_mut());
    interface.configure("10.0.0.1", interface::NetMode::Tun);

    // Set up graceful shutdown signal handler (Ctrl+C)
    let keep_running = Arc::new(AtomicBool::new(true));
    let r = keep_running.clone();

    if let Err(err) = ctrlc::set_handler(move || {
        println!("\nInterrupt received, shutting down gracefully...");
        r.store(false, Ordering::SeqCst);
    }) {
        eprintln!("Error setting Ctrl-C handler: {err}");
    }

    // Initialize ToxVPN core instance from toxvpn.rs
    let mut toxvpn_core = toxvpn::ToxVpnCore::default();

    println!("ToxVPN is running. Press Ctrl+C to exit.");

    // Main execution loop
    while keep_running.load(Ordering::SeqCst) {
        // Keep the main thread alive while background threads handle events
        std::thread::sleep(Duration::from_millis(50));
    }

    println!("ToxVPN exited successfully.");
}
