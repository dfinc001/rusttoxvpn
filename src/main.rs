mod tox_core;
mod interface;

use std::env;
use interface::{NetworkInterface, NetMode};
use tox_core::ToxInstance;
use rand::seq::SliceRandom;

// Small word list for auto-generating 3-word passwords (e.g., light-sky-dog)
const WORD_LIST: &[&str] = &[
    "light", "sky", "dog", "fast", "blue", "run", "red", "car", 
    "jump", "cold", "wind", "storm", "dark", "moon", "night",
    "safe", "iron", "pine", "gold", "open", "firm", "apex"
];

fn generate_default_password() -> String {
    let mut rng = rand::thread_rng();
    let w1 = WORD_LIST.choose(&mut rng).unwrap();
    let w2 = WORD_LIST.choose(&mut rng).unwrap();
    let w3 = WORD_LIST.choose(&mut rng).unwrap();
    format!("{w1}-{w2}-{w3}")
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    let mut is_server = false;
    let mut password: Option<String> = None;
    let mut client_target_id: Option<String> = None;

    // Simple manual argument parser
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--server" => {
                is_server = true;
            }
            "-p" => {
                if i + 1 < args.len() {
                    password = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-id" => {
                if i + 1 < args.len() {
                    client_target_id = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }

    println!("Starting ToxVPN (Rust port)...");

    // 1. Initialize real Tox Core instance via FFI
    let tox = match ToxInstance::new() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to initialize Tox instance: {e}");
            std::process::exit(1);
        }
    };

    let tox_id = tox.get_address_hex();

    // 2. Resolve password if server mode
    let final_password = if is_server {
        password.unwrap_or_else(|| {
            let generated = generate_default_password();
            generated
        })
    } else {
        password.unwrap_or_default()
    };

    // 3. Initialize network interface
    let mut net_iface = NetworkInterface::new(tox.ptr);

    // 4. Configure TUN interface with dynamic local IP based on mode
    let local_ip = if is_server { "192.168.222.1" } else { "192.168.222.2" };
    net_iface.configure(local_ip, NetMode::Tun);

    if is_server {
        println!("\n============================================================");
        println!(" ToxVPN SERVER MODE ACTIVE");
        println!("============================================================");
        println!(" Server Tox ID : {}", tox_id);
        println!(" Shared Password: {}", final_password);
        println!("------------------------------------------------------------");
        println!(" Run the following command on your client container:");
        println!("   cargo run -- -id {} -p {}", tox_id, final_password);
        println!("============================================================\n");
    } else {
        println!("ToxVPN CLIENT MODE ACTIVE");
        if let Some(ref target) = client_target_id {
            println!("Connecting to Server ID: {}", target);
            println!("Using Password         : {}", final_password);
        } else {
            eprintln!("Warning: No server ID specified. Use -id <toxid>");
        }
    }

    println!("TUN interface configured successfully with IP {local_ip}. Running main loop...");

    // 5. Main event loop driving Tox core
    loop {
        unsafe {
            tox_core::tox_iterate(tox.ptr);
            let interval = tox_core::tox_iteration_interval(tox.ptr);
            std::thread::sleep(std::time::Duration::from_millis(interval as u64));
        }
    }
}
