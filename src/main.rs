mod tox_core;
mod interface;
mod bootstrap;

use interface::{NetworkInterface, NetMode};
use tox_core::ToxInstance;
use rand::seq::SliceRandom;
use std::env;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::os::unix::io::RawFd;
use std::sync::OnceLock;

// Small word list for auto-generating 3-word passwords
const WORD_LIST: &[&str] = &[
    "light", "sky", "dog", "fast", "blue", "run", "red", "car",
    "jump", "cold", "wind", "storm", "dark", "moon", "night",
    "safe", "iron", "pine", "gold", "open", "firm", "apex"
];

fn generate_default_password() -> String {
    let mut rng = rand::thread_rng();
    let w1 = WORD_LIST.choose(&mut rng).unwrap_or(&"light");
    let w2 = WORD_LIST.choose(&mut rng).unwrap_or(&"sky");
    let w3 = WORD_LIST.choose(&mut rng).unwrap_or(&"dog");
    format!("{w1}-{w2}-{w3}")
}

// Thread-safe state using safe concurrency primitives instead of static mut
static SERVER_PASSWORD: OnceLock<Mutex<String>> = OnceLock::new();
static GLOBAL_ROUTES: OnceLock<Arc<Mutex<Vec<interface::Route>>>> = OnceLock::new();
static IS_SERVER_NODE: AtomicBool = AtomicBool::new(false);
static TUN_FD: OnceLock<RawFd> = OnceLock::new();

unsafe extern "C" fn on_friend_request(
    tox: *mut std::ffi::c_void,
    public_key: *const u8,
    message: *const u8,
    length: usize,
    _user_data: *mut std::ffi::c_void,
) {
    if message.is_null() || length == 0 || public_key.is_null() {
        eprintln!("[-] Received invalid friend request pointers/length.");
        return;
    }

    let message_slice = std::slice::from_raw_parts(message, length);
    let request_payload = String::from_utf8_lossy(message_slice);

    // Secure split handling (expecting password:ip format)
    let mut parts = request_payload.splitn(2, ':');
    let client_password = parts.next().unwrap_or("");
    let client_ip = parts.next().unwrap_or("192.168.222.2");

    let mut pubkey_array = [0u8; 32];
    std::ptr::copy_nonoverlapping(public_key, pubkey_array.as_mut_ptr(), 32);
    let pubkey_hex = hex::encode(pubkey_array);

    println!("\n[+] Received incoming connection request!");
    println!("    - Client Public Key : {}", pubkey_hex);
    println!("    - Client Tunnel IP  : {}", client_ip);

    if let Some(pwd_mutex) = SERVER_PASSWORD.get() {
        if let Ok(server_pwd) = pwd_mutex.lock() {
            if client_password == *server_pwd {
                println!("    - Authentication    : SUCCESSFUL. Auto-accepting peer...");
                let mut err = 0;
                let friend_number = tox_core::tox_friend_add_norequest(tox, public_key, &mut err);
                if err != 0 {
                    eprintln!("[-] Failed to accept friend, error code: {err}");
                } else {
                    println!("    - Assigned Friend ID: #{friend_number}");
                }
                return;
            }
        }
    }
    eprintln!("    - Authentication    : FAILED (Password mismatch). Rejecting request.");
}

unsafe extern "C" fn on_connection_status(
    _tox: *mut std::ffi::c_void,
    friend_number: u32,
    connection_status: u32,
    _user_data: *mut std::ffi::c_void,
) {
    let is_server = IS_SERVER_NODE.load(Ordering::Acquire);
    match connection_status {
        0 => {
            println!("\n[-] Friend #{friend_number} went OFFLINE.");
            if let Some(routes_arc) = GLOBAL_ROUTES.get() {
                if let Ok(mut routes) = routes_arc.lock() {
                    routes.retain(|r| r.friend_number != friend_number as i32);
                }
            }
        }
        1 | 2 => {
            let conn_type = if connection_status == 1 { "TCP" } else { "UDP" };
            let peer_ip = if is_server {
                Ipv4Addr::new(192, 168, 222, 2)
            } else {
                Ipv4Addr::new(192, 168, 222, 1)
            };

            println!("\n============================================================");
            println!(" PEER CONNECTION ESTABLISHED ({conn_type})");
            println!("============================================================");
            println!(" - Connected Friend ID : #{}", friend_number);
            println!(" - Protocol            : {}", conn_type);
            println!(" - Remote Tunnel IP    : {}", peer_ip);
            println!("============================================================\n");

            if let Some(routes_arc) = GLOBAL_ROUTES.get() {
                if let Ok(mut routes) = routes_arc.lock() {
                    if !routes.iter().any(|r| r.friend_number == friend_number as i32) {
                        routes.push(interface::Route {
                            network: peer_ip,
                            mask: Ipv4Addr::new(255, 255, 255, 255),
                            maskbits: 32,
                            friend_number: friend_number as i32,
                            netmode: NetMode::Tun,
                            pubkey: [0u8; 32],
                        });
                        println!("[*] Added dynamic VPN routing rule for {}", peer_ip);
                    }
                }
            }
        }
        _ => {}
    }
}

unsafe extern "C" fn on_lossy_packet(
    _tox: *mut std::ffi::c_void,
    _friend_number: u32,
    data: *const u8,
    length: usize,
    _user_data: *mut std::ffi::c_void,
) {
    if length > 1 && !data.is_null() {
        if *data == 200 {
            let packet_slice = std::slice::from_raw_parts(data.add(1), length - 1);
            if let Some(&tun_fd) = TUN_FD.get() {
                if tun_fd >= 0 {
                    libc::write(tun_fd, packet_slice.as_ptr() as *const _, packet_slice.len());
                }
            }
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
            "--server" => { is_server = true; }
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

    let tox = match ToxInstance::new() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to initialize Tox instance: {e}");
            eprintln!("This usually happens because the 'toxcore' library is missing from your system.");
            eprintln!("Toxcore is the essential engine that handles the networking, encryption, and peer-to-peer connections that make this VPN work.");
            eprintln!("Please install toxcore for your distribution. For example, on Ubuntu or Debian, you can use: sudo apt install libtoxcore2");
            std::process::exit(1);
        }
    };

    let tox_id = tox.get_address_hex();
    bootstrap::bootstrap_tox(tox.ptr);

    let final_password = if is_server {
        password.unwrap_or_else(generate_default_password)
    } else {
        password.unwrap_or_default()
    };

    if is_server {
        let _ = SERVER_PASSWORD.set(Mutex::new(final_password.clone()));
    }

    let mut net_iface = NetworkInterface::new(tox.ptr);
    let local_ip = if is_server { "192.168.222.1" } else { "192.168.222.2" };
    net_iface.configure(local_ip, NetMode::Tun);

    IS_SERVER_NODE.store(is_server, Ordering::Release);
    let _ = GLOBAL_ROUTES.set(Arc::clone(&net_iface.routes));
    let _ = TUN_FD.set(net_iface.fd);

    unsafe {
        if is_server {
            tox_core::tox_callback_friend_request(tox.ptr, Some(on_friend_request));
        }
        tox_core::tox_callback_friend_connection_status(tox.ptr, Some(on_connection_status));
        tox_core::tox_callback_friend_lossy_packet(tox.ptr, Some(on_lossy_packet));
    }

    if is_server {
        let public_ip = bootstrap::get_public_ip();
        println!("\n============================================================");
        println!(" ToxVPN SERVER MODE ACTIVE");
        println!("============================================================");
        println!(" Server Public IP : {}", public_ip);
        println!(" Server Tox ID    : {}", tox_id);
        println!(" Shared Password  : {}", final_password);
        println!("------------------------------------------------------------");
        println!(" Run on client container:");
        println!("    sudo toxvpn -id {} -p {}", tox_id, final_password);
        println!("============================================================\n");
    } else {
        println!("\n============================================================");
        println!(" ToxVPN CLIENT MODE ACTIVE");
        println!("============================================================");
        println!(" Local Tunnel IP: {}", local_ip);
        if let Some(ref target_id_hex) = client_target_id {
            println!(" Target Server ID: {}", target_id_hex);
            println!(" Using Password  : {}", final_password);

            let target_bytes = match hex::decode(target_id_hex) {
                Ok(bytes) if bytes.len() == 38 => bytes,
                _ => {
                    eprintln!("[-] Error: Invalid hex string or length for server ID (must be 32 bytes).");
                    std::process::exit(1);
                }
            };

            let request_message = format!("{}:{}", final_password, local_ip);
            let pass_bytes = request_message.as_bytes();

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
                eprintln!("[-] Failed to send friend request, error code: {err}");
            } else {
                println!("[+] Friend request sent to server with IP info! Assigned index: #{friend_number}");
            }
        } else {
            eprintln!("[-] Warning: No server ID specified. Use -id <toxid>");
        }
        println!("============================================================\n");
    }

    println!("TUN interface configured successfully with IP {local_ip}. Running main loop...");

    loop {
        while let Ok(pkt) = net_iface.rx_channel.try_recv() {
            let mut err = 0;
            unsafe {
                tox_core::tox_friend_send_lossy_packet(
                    tox.ptr,
                    pkt.friend_number,
                    pkt.data.as_ptr(),
                    pkt.data.len(),
                    &mut err,
                );
            }
        }

        unsafe {
            tox_core::tox_iterate(tox.ptr, std::ptr::null_mut());
            let interval = tox_core::tox_iteration_interval(tox.ptr);
            std::thread::sleep(std::time::Duration::from_millis(interval as u64));
        }
    }
}
