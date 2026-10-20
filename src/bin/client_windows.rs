// To run: cargo build --bin client_windows --target x86_64-pc-windows-msvc
// (Requires wintun.dll in the same directory)

use std::sync::Arc;
use std::env;
use std::time::Duration;

fn main() {
    println!("Starting ToxVPN Windows Client...");

    // 1. Load Wintun and create adapter
    let wintun = unsafe { wintun::load().expect("Failed to load wintun.dll") };
    let adapter = match wintun::Adapter::open(&wintun, "ToxVPN") {
        Ok(a) => a,
        Err(_) => wintun::Adapter::create(&wintun, "ToxVPN", "ToxVPN Tunnel", None)
            .expect("Failed to create Wintun adapter. Are you running as Administrator?"),
    };

    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)
        .expect("Failed to start Wintun session"));

    // 2. Configure IP via netsh
    let _ = std::process::Command::new("netsh")
        .args(&["interface", "ipv4", "set", "address", "name=\"ToxVPN\"", "source=static", "192.168.222.2", "255.255.255.0"])
        .status();

    println!("[+] Wintun interface active and configured with IP 192.168.222.2");

    // 3. Initialize Tox Core & Connect to Linux Server ID...
    // (You can hook your existing tox_core bindings here)
    
    let session_reader = Arc::clone(&session);
    
    // Background thread: Read from Windows TUN (Wintun) -> Send to Tox peer
    std::thread::spawn(move || {
        loop {
            match session_reader.receive_blocking() {
                Ok(packet) => {
                    let bytes = packet.bytes();
                    // Prepend your protocol header (e.g., 200) and send via tox_friend_send_lossy_packet
                    // to your Linux server friend index.
                }
                Err(_) => break,
            }
        }
    });

    // Main event loop for Tox iteration
    loop {
        // tox_iterate(...)
        std::thread::sleep(Duration::from_millis(20));
    }
}
