mod tox_core;
mod interface;

use interface::{NetworkInterface, NetMode};
use tox_core::ToxInstance;
use rand::seq::SliceRandom;
use std::env;

// Small word list for auto-generating 3-word passwords (e.g., light-sky-dog)
const WORD_LIST: &[&str] = &[
    "light", "sky", "dog", "fast", "blue", "run", "red", "car", 
    "jump", "cold", "wind", "storm", "dark", "moon", "night",
    "safe", "iron", "pine", "gold", "open", "firm", "apex"
];

/// Generates a random 3-word hyphenated password if none is provided via CLI.
fn generate_default_password() -> String {
    let mut rng = rand::thread_rng();
    let w1 = WORD_LIST.choose(&mut rng).unwrap();
    let w2 = WORD_LIST.choose(&mut rng).unwrap();
    let w3 = WORD_LIST.choose(&mut rng).unwrap();
    format!("{w1}-{w2}-{w3}")
}

// Global variable to store the server password so the C callback can access it.
static mut SERVER_PASSWORD: String = String::new();

/// C-compatible callback function triggered by libtoxcore when an incoming friend request arrives.
unsafe extern "C" fn on_friend_request(
    tox: *mut std::ffi::c_void,
    public_key: *const u8,
    message: *const u8,
    length: usize,
    _user_data: *mut std::ffi::c_void,
) {
    // Reconstruct the message slice sent by the client (which contains our shared password)
    let message_slice = std::slice::from_raw_parts(message, length);
    let client_password = String::from_utf8_lossy(message_slice);

    // Convert raw 32-byte public key to hex for clean logging
    let mut pubkey_array = [0u8; 32];
    std::ptr::copy_nonoverlapping(public_key, pubkey_array.as_mut_ptr(), 32);
    let pubkey_hex = hex::encode(pubkey_array);

    println!("Received friend request from public key: {}", pubkey_hex);
    println!("Provided password: '{}'", client_password);

    // Verify password against our expected server password
    if client_password == SERVER_PASSWORD {
        println!("Password verified! Auto-accepting connection...");
        let mut err = 0;
        let friend_number = tox_core::tox_friend_add_norequest(tox, public_key, &mut err);
        if err != 0 {
            eprintln!("Failed to accept friend, error code: {err}");
        } else {
            println!("Successfully accepted peer as friend number: {friend_number}");
        }
    } else {
        eprintln!("Password mismatch! Rejecting connection request.");
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    let mut is_server = false;
    let mut password: Option<String> = None;
    let mut client_target_id: Option<String> = None;

    // Manual command-line argument parser
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

    // 2. Resolve password (auto-generate if server and none provided)
    let final_password = if is_server {
        password.unwrap_or_else(|| generate_default_password())
    } else {
        password.unwrap_or_default()
    };

    // 3. If in server mode, register the friend request callback
    if is_server {
        unsafe {
            SERVER_PASSWORD = final_password.clone();
            tox_core::tox_callback_friend_request(tox.ptr, Some(on_friend_request));
        }
    }

    // 4. Initialize network interface
    let mut net_iface = NetworkInterface::new(tox.ptr);

    // 5. Configure TUN interface with dynamic local IP based on mode
    // Server gets 192.168.222.1, Client gets 192.168.222.2
    let local_ip = if is_server { "192.168.222.1" } else { "192.168.222.2" };
    net_iface.configure(local_ip, NetMode::Tun);

    // 6. Print startup instructions & handle client-side friend connection request
    if is_server {
        println!("\n============================================================");
        println!(" ToxVPN SERVER MODE ACTIVE");
        println!("============================================================");
        println!(" Server Tox ID : {}", tox_id);
        println!(" Shared Password: {}", final_password);
        println!("------------------------------------------------------------");
        println!(" Run on client container:");
        println!("   cargo run -- -id {} -p {}", tox_id, final_password);
        println!("============================================================\n");
    } else {
        println!("ToxVPN CLIENT MODE ACTIVE");
        if let Some(ref target_id_hex) = client_target_id {
            println!("Connecting to Server ID: {}", target_id_hex);
            println!("Using Password         : {}", final_password);

            // Decode 76-character hex string into 38-byte binary Tox address
            let target_bytes = hex::decode(target_id_hex).expect("Invalid hex string for server ID");
            let pass_bytes = final_password.as_bytes();

            let mut err = 0;
            let friend_number = unsafe {
                tox_core::tox_friend_add(
                    tox.ptr,
                    target_bytes.as_ptr(),
                    pass_bytes.as_ptr(),
                    pass_bytes.len(),
                    &mut err,
                )
            };

            if err != 0 {
                eprintln!("Failed to add friend / send request, error code: {err}");
            } else {
                println!("Friend request sent to server! Friend index: {friend_number}");
            }
        } else {
            eprintln!("Warning: No server ID specified. Use -id <toxid>");
        }
    }

    println!("TUN interface configured successfully with IP {local_ip}. Running main loop...");

    // 7. Main event loop keeping Tox core active and responsive
    loop {
        unsafe {
            tox_core::tox_iterate(tox.ptr);
            let interval = tox_core::tox_iteration_interval(tox.ptr);
            std::thread::sleep(std::time::Duration::from_millis(interval as u64));
        }
    }
}
