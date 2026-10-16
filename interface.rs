use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;

pub const TOX_PUBLIC_KEY_SIZE: usize = 32;

/// Networking mode for the interface or peers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetMode {
    Tun = 0,
    Tap = 1,
}

/// Represents a routing entry for a peer on the VPN network
#[derive(Debug, Clone)]
pub struct Route {
    pub network: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub maskbits: i32,
    pub friend_number: i32,
    pub netmode: NetMode,
    pub pubkey: [u8; TOX_PUBLIC_KEY_SIZE],
}

/// Manages the virtual TUN/TAP network interface, packet routing, and peer communication
pub struct NetworkInterface {
    pub routes: Vec<Route>,
    fd: RawFd,
    my_tox: *mut std::ffi::c_void, // Opaque pointer to Tox core
    interface_index: i32,
    mymac: [u8; 6],
}

impl NetworkInterface {
    pub fn new(fd: RawFd, my_tox: *mut std::ffi::c_void, interface_index: i32) -> Self {
        Self {
            routes: Vec::new(),
            fd,
            my_tox,
            interface_index,
            mymac: [0u8; 6],
        }
    }

    /// Converts a Tox public key into a valid local MAC address
    pub fn pubkey_to_mac(pubkey: &[u8], mac: &mut [u8]) {
        if pubkey.len() >= 6 && mac.len() >= 6 {
            mac[..6].copy_from_slice(&pubkey[..6]);
            mac[0] |= 2;  // Locally administered bit
            mac[0] &= 254; // Unicast bit
        }
    }

    /// Checks if a MAC address is multicast
    pub fn mac_is_multicast(mac: &[u8]) -> bool {
        !mac.is_empty() && (mac[0] & 1) != 0
    }

    /// Finds a matching route for a given destination IP address
    pub fn find_route(&self, peer: Ipv4Addr) -> Option<Route> {
        let peer_bits = u32::from(peer);
        for route in &self.routes {
            let net_bits = u32::from(route.network);
            let mask_bits = u32::from(route.mask);
            if (net_bits & mask_bits) == (peer_bits & mask_bits) {
                return Some(route.clone());
            }
        }
        None
    }

    /// Adds a peer route and configures the system route table
    pub fn add_peer_route(&mut self, peer: Ipv4Addr, friend_number: i32, peer_netmode: NetMode, pubkey: &[u8]) {
        let mut key = [0u8; TOX_PUBLIC_KEY_SIZE];
        if pubkey.len() == TOX_PUBLIC_KEY_SIZE {
            key.copy_from_slice(pubkey);
        }

        let route = Route {
            network: peer,
            mask: Ipv4Addr::new(255, 255, 255, 255),
            maskbits: 32,
            friend_number,
            netmode: peer_netmode,
            pubkey: key,
        };

        self.routes.push(route);
        // TODO: Call systemRouteDirect(self.interface_index, peer);
    }

    pub fn set_peer_ip(&mut self, peer: Ipv4Addr, friend_number: i32, peer_netmode: NetMode, pubkey: &[u8]) {
        self.add_peer_route(peer, friend_number, peer_netmode, pubkey);
    }

    pub fn remove_peer(&mut self, friend_number: i32) {
        self.routes.retain(|r| r.friend_number != friend_number);
    }

    /// Forwards a packet to a specific peer via Tox custom lossy packets
    pub fn forward_packet(&self, route: &Route, readbuffer: &[u8], netmode: NetMode) {
        let mut buffer = vec![0u8; readbuffer.len() + 1];
        buffer[0] = 200; // Tox-specific VPN packet prefix identifier

        let payload_size = if route.netmode == NetMode::Tun {
            // Strip headers for TUN mode targets (keeping packet payload + PI)
            let pi_size = std::mem::size_of::<libc::tun_pi>();
            if readbuffer.len() < pi_size {
                return;
            }
            buffer[1..1 + pi_size].copy_from_slice(&readbuffer[..pi_size]);
            let offset = pi_size + 14; // tun_pi + ethernet_header size
            if readbuffer.len() < offset {
                return;
            }
            let remaining = &readbuffer[offset..];
            buffer[1 + pi_size..1 + pi_size + remaining.len()].copy_from_slice(remaining);
            pi_size + remaining.len()
        } else {
            // TAP mode forwards the full packet
            buffer[1..1 + readbuffer.len()].copy_from_slice(readbuffer);
            readbuffer.len()
        };

        // FFI call placeholder to send via Tox:
        // tox_friend_send_lossy_packet(self.my_tox, route.friend_number, buffer.as_ptr(), payload_size as u32 + 1, &mut error);
        let _ = (netmode, payload_size);
    }

    /// Broadcasts a packet to all connected TAP peers
    pub fn broadcast_packet(&self, readbuffer: &[u8]) {
        for route in &self.routes {
            if route.netmode == NetMode::Tap {
                self.forward_packet(route, readbuffer, NetMode::Tap);
            }
        }
    }

    /// Sends packets received from peers into the local OS kernel interface
    pub fn send_pi_packet_to_kernel(&self, data: &[u8]) {
        if self.fd >= 0 {
            let mut write_data = data.to_vec();
            let mut size = write_data.len();

            // If TUN mode, strip the leading Ethernet header before writing to kernel
            let pi_size = std::mem::size_of::<libc::tun_pi>();
            let eth_size = 14;
            if size >= pi_size + eth_size {
                let mut stripped = Vec::with_capacity(size - eth_size);
                stripped.extend_from_slice(&write_data[..pi_size]);
                stripped.extend_from_slice(&write_data[pi_size + eth_size..]);
                write_data = stripped;
                size = write_data.len();
            }

            let ret = unsafe { libc::write(self.fd, write_data.as_ptr() as *const _, size) };
            if ret < 0 || ret as usize != size {
                eprintln!("Partial or failed packet write to TUN interface");
            }
        } else {
            eprintln!("TUN file descriptor not open");
        }
    }
}
