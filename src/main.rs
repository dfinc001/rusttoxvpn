mod tox_core;
mod interface;

use interface::{NetworkInterface, NetMode};
use tox_core::ToxInstance;

fn main() {
    println!("Starting ToxVPN (Rust port)...");

    // 1. Initialize real Tox Core instance via FFI
    let tox = match ToxInstance::new() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to initialize Tox instance: {e}");
            std::process::exit(1);
        }
    };

    // 2. Print the real 76-character Tox ID
    let tox_id = tox.get_address_hex();
    println!("Real Tox ID: {}", tox_id);

    // 3. Initialize network interface, passing the raw Tox pointer
    let mut net_iface = NetworkInterface::new(tox.ptr);

    // 4. Configure TUN interface with dynamic local IP (e.g., 192.168.222.154 for client)
    // You can make this command-line argument driven or dynamic as needed.
    let local_ip = "192.168.222.154"; 
    net_iface.configure(local_ip, NetMode::Tun);

    println!("TUN interface configured successfully with IP {local_ip}. Running main loop...");

    // 5. Main iteration loop keeping Tox core alive
    loop {
        // We will add tox_iterate and interval sleeping here next!
        std::thread::sleep(std::-duration::Duration::from_millis(50));
    }
}
