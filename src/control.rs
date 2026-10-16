use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::io::FromRawFd;
use std::os::unix::io::RawFd;

// Placeholder types for external modules
pub struct NetworkInterface {
    pub routes: Vec<super::interface::Route>,
}

impl NetworkInterface {
    pub fn remove_peer(&mut self, friend_number: i32) {
        self.routes.retain(|r| r.friend_number != friend_number);
    }
}

pub struct Tox;
pub struct ToxVpnCore;

/// Handles interactive user control commands (from stdin or unix client sockets)
pub struct Control {
    pub handle: RawFd,
    interface: *mut NetworkInterface,
    reader: Option<BufReader<File>>,
    writer: Option<File>,
    is_stdin: bool,
}

impl Control {
    /// Creates a control instance bound to standard input/output
    pub fn new_stdin(interface: &mut NetworkInterface) -> Self {
        Self {
            handle: 0, // STDIN_FILENO
            interface,
            reader: None,
            writer: None,
            is_stdin: true,
        }
    }

    /// Creates a control instance bound to an accepted client socket descriptor
    pub fn new_socket(interface: &mut NetworkInterface, socket: RawFd) -> Self {
        // Convert raw file descriptor into Rust file handles safely
        let file_read = unsafe { File::from_raw_fd(socket) };
        let file_write = file_read.try_clone().unwrap_or_else(|_| {
            unsafe { File::from_raw_fd(socket) }
        });

        Self {
            handle: socket,
            interface,
            reader: Some(BufReader::new(file_read)),
            writer: Some(file_write),
            is_stdin: false,
        }
    }

    /// Reads a command line and processes administrative instructions (list, add, remove, whitelist, status, route, etc.)
    pub fn handle_read_data(&mut self, tox: &mut Tox, toxvpn: &mut ToxVpnCore) -> isize {
        let mut line = String::new();
        
        let bytes_read = if self.is_stdin {
            let stdin = io::stdin();
            match stdin.read_line(&mut line) {
                Ok(n) if n == 0 => return -1,
                Ok(n) => n as isize,
                Err(_) => return -1,
            }
        } else if let Some(ref mut reader) = self.reader {
            match reader.read_line(&mut line) {
                Ok(n) if n == 0 => return -1,
                Ok(n) => n as isize,
                Err(_) => return -1,
            }
        } else {
            return -1;
        };

        let mut parts = line.split_whitespace();
        let cmd = match parts.next() {
            Some(c) => c,
            None => return bytes_read,
        };

        // Handle output writing target (stdout or socket stream)
        let mut out: Box<dyn Write> = if self.is_stdin {
            Box::new(io::stdout())
        } else if let Some(ref mut writer) = self.writer {
            Box::new(writer.try_clone().unwrap())
        } else {
            Box::new(io::sink())
        };

        match cmd {
            "list" => {
                let _ = writeln!(out, "listing friends");
                // TODO: Query tox friends list, display connection states and last online timestamps safely
            }
            "remove" => {
                if let Some(id_str) = parts.next() {
                    if let Ok(friendid) = id_str.parse::<i32>() {
                        let _ = writeln!(out, "going to kick {friendid}");
                        // FFI call: tox_friend_delete(tox, friendid as u32, std::ptr::null_mut());
                        unsafe {
                            if !self.interface.is_null() {
                                (*self.interface).remove_peer(friendid);
                            }
                        }
                    }
                }
            }
            "add" => {
                if let Some(toxid) = parts.next() {
                    let _ = writeln!(out, "going to connect to {toxid}");
                    // TODO: Convert hex toxid to binary and call tox_friend_add
                }
            }
            "whitelist" => {
                if let Some(toxid) = parts.next() {
                    let _ = writeln!(out, "whitelisting node: {toxid}");
                    // TODO: Call tox_friend_add_norequest
                }
            }
            "status" => {
                let _ = writeln!(out, "status query requested");
            }
            "help" => {
                let _ = writeln!(out, "list                - lists tox friends");
                let _ = writeln!(out, "remove <number>     - removes a friend");
                let _ = writeln!(out, "add <toxid>         - adds a friend");
                let _ = writeln!(out, "whitelist <toxid>   - add/accept a friend");
                let _ = writeln!(out, "status              - shows own id & ip");
                let _ = writeln!(out, "bootstrap           - attempt to reconnect");
            }
            "bootstrap" => {
                let _ = writeln!(out, "Triggering manual bootstrap...");
                super::do_bootstrap(tox, toxvpn);
            }
            "route" => {
                if let Some(sub) = parts.next() {
                    if sub == "show" {
                        unsafe {
                            if !self.interface.is_null() {
                                for r in &(*self.interface).routes {
                                    let _ = writeln!(out, "{}/{} via friend#{}", r.network, r.maskbits, r.friend_number);
                                }
                            }
                        }
                    }
                }
            }
            _ => {
                let _ = writeln!(out, "Unknown command. Type 'help' for options.");
            }
        }

        let _ = out.flush();
        bytes_read
    }
}
