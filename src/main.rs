mod tox_core;
mod interface;

use interface::{NetworkInterface, NetMode};
use tox_core::ToxInstance;
use rand::seq::SliceRandom;
use std::env;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

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

// Global shared state for callbacks to access routing and passwords
static mut SERVER_PASSWORD: String = String::new();
static mut GLOBAL_ROUTES: Option<Arc<Mutex<Vec<interface::Route>>>> = None;
static mut IS_SERVER_NODE: bool = false;

/// Bootstraps the Tox instance onto the global DHT network
fn bootstrap_tox(tox_ptr: *mut std::ffi::c_void) {
    let host = std::ffi::CString::new("node.tox.chat").unwrap();
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
        println!("[+] Successfully initiated DHT bootstrap!");
    } else {
        eprintln!("[-] Failed to bootstrap DHT, error code: {err}");
    }
}

/// C-compatible callback function triggered by libtoxcore when an incoming friend request arrives.
unsafe extern "C" fn on_friend_request(
    tox: *mut std::ffi::c_void,
    public_key: *const u8,
    message: *const u8,
    length: usize,
    _user_data: *mut std::ffi::c_void,
) {
    let message_slice = std::slice::from_raw_parts(message, length);
    let client_password = String::from_utf8_lossy(message_slice);

    let mut pubkey_array = [0u8; 32];
    std::ptr::copy_nonoverlapping(public_key, pubkey_array.as_mut_ptr(), 32);
    let pubkey_hex = hex::encode(pubkey_array);

    println!("Received friend request from public key: {}", pubkey_hex);
    println!("Provided password: '{}'", client_password);

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

/// C-compatible callback function triggered when a friend's connection status changes.
unsafe extern "C" fn on_connection_status(
    _tox: *mut std::ffi::c_void,
    friend_number: u32,
    connection_status: u32,
    _user_data: *mut std::ffi::c_void,
) {
    match connection_status {
        0 => {
            println!("[-] Friend {friend_number} went OFFLINE.");
            if let Some(ref routes_arc) = GLOBAL_ROUTES {
                let mut routes = routes_arc.lock().unwrap();
                routes.retain(|r| r.friend_number != friend_number as i32);
            }
        }
        1 | 2 => {
            let conn_type = if connection_status == 1 { "TCP" } else { "UDP" };
            println!("[+] Friend {friend_number} connected via {conn_type}!");

            // Populate point-to-point route table upon connection
            if let Some(ref routes_arc) = GLOBAL_ROUTES {
                let mut routes = routes_arc.lock().unwrap();
                
                let peer_ip = if IS_SERVER_NODE {
                    Ipv4Addr::new(192, 168, 222, 2)
                } else {
                    Ipv4Addr::new(192, 168, 222, 1)
                };

                if !routes.iter().any(|r| r.friend_number == friend_number as i32) {
                    routes.push(interface::Route {
                        network: peer_ip,
                        mask: Ipv4Addr::new(255, 255, 255, 255),
                        maskbits: 32,
                        friend_number: friend_number as i32,
                        netmode: NetMode::Tun,
                        pubkey: [0u8; 32],
                    });
                    println!("[*] Added VPN route to {} -> Friend {friend_number}", peer_ip);
                }
            }
        }
        _ => {}
    }
}

/// C-compatible callback function triggered when a custom lossy packet arrives from a friend.
unsafe extern "C" fn on_lossy_packet(
    _tox: *mut std::ffi::c_void,
    _friend_number: u32,
    data: *const u8,
    length: usize,
    user_data: *mut std::ffi::c_void,
) {
    if length > 1 && data.read() == 200 {
        let packet_slice = std::slice::from_raw_parts(data.add(1), length - 1);
        if !user_data.is_null() {
            let net_iface = &*(user_data as *const NetworkInterface);
            net_iface.send_pi_packet_to_kernel(packet_slice);
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    let mut is_server = false;
    let mut password: Option<String> = None;
    let mut client_target_id: Option<String> = None;

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

    // 2. Bootstrap onto the public Tox DHT network
    bootstrap_tox(tox.ptr);

    // 3. Resolve password (auto-generate if server and none provided)
    let final_password = if is_server {
        password.unwrap_or_else(|| generate_default_password())
    } else {
        password.unwrap_or_default()
    };

    // 4. Initialize network interface
    let mut net_iface = NetworkInterface::new(tox.ptr);

    // 5. Configure TUN interface with dynamic local IP based on mode
    let local_ip = if is_server { "192.168.222.1" } else { "192.168.222.2" };
    net_iface.configure(local_ip, NetMode::Tun);

    // 6. Setup global state for callbacks
    unsafe {
        IS_SERVER_NODE = is_server;
        GLOBAL_ROUTES = Some(Arc::clone(&net_iface.routes));
        
        if is_server {
            SERVER_PASSWORD = final_password.clone();
            tox_core::tox_callback_friend_request(tox.ptr, Some(on_friend_request));
        }
        tox_core::tox_callback_friend_connection_status(tox.ptr, Some(on_connection_status));
        tox_core::tox_callback_friend_lossy_packet(tox.ptr, Some(on_lossy_packet));
    }

    // 7. Print startup instructions & handle client-side friend connection request
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

    // 8. Main event loop keeping Tox core active and responsive
    loop {
        unsafe {
            tox_core::tox_iterate(tox.ptr);
            let interval = tox_core::tox_iteration_interval(tox.ptr);
            std::thread::sleep(std::time::Duration::from_millis(interval as u64));
        }
    }
}
