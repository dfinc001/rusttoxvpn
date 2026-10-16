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

    // 4. Configure TUN interface with dynamic local IP
    let local_ip = "192.168.222.154"; 
    net_iface.configure(local_ip, NetMode::Tun);

    println!("TUN interface configured successfully with IP {local_ip}. Running main loop...");

    // 5. Main event loop driving Tox core and keeping VPN active
    loop {
        unsafe {
            tox_core::tox_iterate(tox.ptr);
            let interval = tox_core::tox_iteration_interval(tox.ptr);
            std::thread::sleep(std::time::Duration::from_millis(interval as u64));
        }
    }
}
