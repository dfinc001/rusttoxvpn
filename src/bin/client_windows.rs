// src/bin/client_windows.rs

// If tox_core, bootstrap, etc. are modules in your src/ directory:
#[path = "../tox_core.rs"]
mod tox_core;
#[path = "../bootstrap.rs"]
mod bootstrap;

use std::sync::Arc;
use std::env;
use std::time::Duration;

// Callback when a lossy packet arrives from the Linux server
unsafe extern "C" fn on_lossy_packet(
    _tox: *mut std::ffi::c_void,
    _friend_number: u32,
    data: *const u8,
    length: usize,
    user_data: *mut std::ffi::c_void,
) {
    if length > 1 && !data.is_null() && *data == 200 {
        let packet_slice = std::slice::from_raw_parts(data.add(1), length - 1);
        
        // Grab the Wintun session pointer passed via user data
        let session = &*(user_data as *const Arc<wintun::Session>);
        if let Ok(mut packet) = session.allocate_send_packet(packet_slice.len() as u16) {
            packet.bytes_mut().copy_from_slice(packet_slice);
            session.send_packet(packet);
        }
    }
}

unsafe extern "C" fn on_connection_status(
    _tox: *mut std::ffi::c_void,
    friend_number: u32,
    connection_status: u32,
    _user_data: *mut std::ffi::c_void,
) {
    match connection_status {
        1 | 2 => {
            let conn_type = if connection_status == 1 { "TCP" } else { "UDP" };
            println!("\n[+] Connected to Linux Server successfully via {}! Friend ID: #{}", conn_type, friend_number);
        }
        0 => {
            println!("\n[-] Connection to Linux Server lost (Offline).");
        }
        _ => {}
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut server_tox_id: Option<String> = None;
    let mut password: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-id" => {
                if i + 1 < args.len() {
                    server_tox_id = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-p" => {
                if i + 1 < args.len() {
                    password = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }

    let target_id = match server_tox_id {
        Some(id) => id,
        None => {
            eprintln!("[-] Error: Missing server Tox ID. Use: cargo run --bin client_windows -- -id <SERVER_TOX_ID> -p <PASSWORD>");
            std::process::exit(1);
        }
    };

    let pass = password.unwrap_or_default();

    println!("============================================================");
    println!(" ToxVPN WINDOWS CLIENT STARTING");
    println!("============================================================");

    // 1. Load Wintun Driver DLL (Must be next to the executable)
    let wintun = unsafe {
        wintun::load().expect("Failed to load wintun.dll. Ensure wintun.dll is next to the executable.")
    };

    // 2. Open or Create Wintun Adapter
    let adapter = match wintun::Adapter::open(&wintun, "ToxVPN") {
        Ok(a) => a,
        Err(_) => wintun::Adapter::create(&wintun, "ToxVPN", "ToxVPN Tunnel", None)
            .expect("Failed to create Wintun adapter. Are you running as Administrator?"),
    };

    let session = Arc::new(
        adapter.start_session(wintun::MAX_RING_CAPACITY)
            .expect("Failed to start Wintun session")
    );

    // 3. Configure local adapter IP via Windows netsh command
    let _ = std::process::Command::new("netsh")
        .args(&[
            "interface", "ipv4", "set", "address",
            "name=\"ToxVPN\"", "source=static",
            "192.168.222.2", "255.255.255.0"
        ])
        .status();

    println!("[+] Virtual TUN interface active: 192.168.222.2");

    // 4. Initialize Tox Core
    let tox = match tox_core::ToxInstance::new() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[-] Failed to initialize Tox instance: {e}");
            std::process::exit(1);
        }
    };

    bootstrap::bootstrap_tox(tox.ptr);

    // Set callbacks
    let session_ptr = Arc::into_raw(Arc::clone(&session)) as *mut std::ffi::c_void;
    unsafe {
        tox_core::tox_callback_friend_connection_status(tox.ptr, Some(on_connection_status));
        tox_core::tox_callback_friend_lossy_packet(tox.ptr, Some(on_lossy_packet));
    }

    // Add Server as a Friend
    let target_bytes = match hex::decode(&target_id) {
        Ok(bytes) if bytes.len() == 38 => bytes,
        _ => {
            eprintln!("[-] Error: Invalid hex string or length for server ID (must be 32 bytes + nospam/checksum).");
            std::process::exit(1);
        }
    };

    let request_message = format!("{}:192.168.222.2", pass);
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
        eprintln!("[-] Failed to send friend request to server, error code: {err}");
    } else {
        println!("[+] Friend request sent to server! Assigned Friend ID: #{}", friend_number);
    }

    println!("============================================================\n");

    // 5. Background thread: Read from Windows Wintun -> Send via Tox Lossy Packet to Server
    let session_reader = Arc::clone(&session);
    let tox_ptr = tox.ptr;
    std::thread::spawn(move || {
        loop {
            match session_reader.receive_blocking() {
                Ok(packet) => {
                    let bytes = packet.bytes();
                    let mut data = vec![200]; // Protocol header matching your Linux server expectation
                    data.extend_from_slice(bytes);

                    let mut send_err = 0;
                    unsafe {
                        tox_core::tox_friend_send_lossy_packet(
                            tox_ptr,
                            friend_number,
                            data.as_ptr(),
                            data.len(),
                            &mut send_err,
                        );
                    }
                }
                Err(_) => break,
            }
        }
    });

    // 6. Main Tox Event Loop
    loop {
        unsafe {
            tox_core::tox_iterate(tox.ptr);
            let interval = tox_core::tox_iteration_interval(tox.ptr);
            std::thread::sleep(Duration::from_millis(interval as u64));
        }
    }
}
