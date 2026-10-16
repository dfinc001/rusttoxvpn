use std::io;
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};

/// Size of a Tox public key in bytes (standard Ed25519 key size used by Tox core)
pub const TOX_PUBLIC_KEY_SIZE: usize = 32;

/// Linux TUN Packet Information (PI) header structure.
/// Prefixed to packets read/written on TUN devices unless IFF_NO_PI is set.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct tun_pi {
    pub flags: u16,
    pub proto: u16,
}

/// Networking mode for the interface or peers (Tun = Layer 3 IP, Tap = Layer 2 Ethernet)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetMode {
    Tun = 0,
    Tap = 1,
}

/// Represents a routing entry for a peer connected on the ToxVPN network
#[derive(Debug, Clone)]
pub struct Route {
    pub network: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub maskbits: i32,
    pub friend_number: i32,
    pub netmode: NetMode,
    pub pubkey: [u8; TOX_PUBLIC_KEY_SIZE],
}

/// Manages the virtual TUN/TAP network interface, packet routing, and peer communication.
/// Uses thread-safe primitives (`Arc<Mutex<...>>`) to share routing tables with background worker threads.
pub struct NetworkInterface {
    pub routes: Arc<Mutex<Vec<Route>>>,
    fd: RawFd,
    my_tox: *mut std::ffi::c_void, // Opaque pointer to the C Tox core instance
    interface_index: i32,
    mymac: [u8; 6],
}

impl NetworkInterface {
    /// Opens the Linux TUN/TAP device driver (/dev/net/tun) and initializes interface structures.
    pub fn new(my_tox: *mut std::ffi::c_void) -> Self {
        // Open the character device file descriptor for read/write access
        let fd = unsafe { libc::open(b"/dev/net/tun\0".as_ptr() as *const _, libc::O_RDWR) };
        if fd < 0 {
            eprintln!("Unable to open /dev/net/tun");
        }

        Self {
            routes: Arc::new(Mutex::new(Vec::new())),
            fd,
            my_tox,
            interface_index: 0,
            mymac: [0u8; 6],
        }
    }

    /// Configures the TUN/TAP interface via ioctl syscalls, sets MAC addresses, MTU, 
    /// local/peer IP addresses, brings the interface up, and launches the background packet reader loop.
    pub fn configure(&mut self, ip_in: &str, netmode: NetMode) {
        if self.fd < 0 {
            eprintln!("TUN file descriptor is invalid.");
            return;
        }

        // Initialize the network interface request structure (`ifreq`)
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        
        ifr.ifr_ifru.ifru_flags = match netmode {
            NetMode::Tap => libc::IFF_TAP as i16,
            NetMode::Tun => libc::IFF_TUN as i16,
        };

        // Assign the virtual interface name "tox_master0"
        let name = b"tox_master0\0";
        unsafe {
            std::ptr::copy_nonoverlapping(
                name.as_ptr() as *const i8,
                ifr.ifr_name.as_mut_ptr(),
                name.len(),
            );
        }

        // Bind the file descriptor to the virtual interface name using TUNSETIFF ioctl
        let err = unsafe { libc::ioctl(self.fd, libc::TUNSETIFF as _, &mut ifr) };
        if err < 0 {
            let errno = unsafe { *libc::__errno_location() };
            if errno == libc::EPERM {
                eprintln!("No permission to create TUN device (run with NET_ADMIN capability)");
                std::process::exit(-1);
            } else if errno == libc::EINVAL {
                eprintln!("EINVAL creating network device, is tun/tap in the right mode?");
                std::process::exit(-1);
            } else {
                eprintln!("Error configuring TUNSETIFF: errno {errno}");
                unsafe { libc::close(self.fd); }
                std::process::exit(-1);
            }
        }

        // Generate local MAC address from Tox public key placeholder
        let pubkey = [0u8; TOX_PUBLIC_KEY_SIZE];
        Self::pubkey_to_mac(&pubkey, &mut self.mymac);

        // Create a temporary standard datagram socket to issue configuration ioctls
        let tun_sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if tun_sock < 0 {
            eprintln!("Error while creating configuration socket");
            return;
        }

        // Set interface MTU to 1200 bytes (optimized for VPN tunnel overhead over UDP)
        unsafe {
            ifr.ifr_ifru.ifru_mtu = 1200;
            libc::ioctl(tun_sock, libc::SIOCSIFMTU as _, &mut ifr);
        }

        // Parse and set the local interface IPv4 address
        let ip_addr: Ipv4Addr = match ip_in.parse() {
            Ok(ip) => ip,
            Err(_) => Ipv4Addr::new(10, 0, 0, 1),
        };

        unsafe {
            let mut addr: libc::sockaddr_in = std::mem::zeroed();
            addr.sin_family = libc::AF_INET as u16;
            addr.sin_addr.s_addr = u32::from(ip_addr).to_be();
            std::ptr::copy_nonoverlapping(
                &addr as *const _ as *const u8,
                &mut ifr.ifr_ifru.ifru_addr as *mut _ as *mut u8,
                std::mem::size_of::<libc::sockaddr_in>(),
            );
            libc::ioctl(tun_sock, libc::SIOCSIFADDR as _, &mut ifr);

            // Set the peer/destination IPv4 address for point-to-point routing
            let dst_ip = Ipv4Addr::new(10, 123, 123, 123);
            addr.sin_addr.s_addr = u32::from(dst_ip).to_be();
            std::ptr::copy_nonoverlapping(
                &addr as *const _ as *const u8,
                &mut ifr.ifr_ifru.ifru_dstaddr as *mut _ as *mut u8,
                std::mem::size_of::<libc::sockaddr_in>(),
            );
            libc::ioctl(tun_sock, libc::SIOCSIFDSTADDR as _, &mut ifr);

            // Bring the interface UP and mark it RUNNING
            libc::ioctl(tun_sock, libc::SIOCGIFFLAGS as _, &mut ifr);
            ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as i16;
            libc::ioctl(tun_sock, libc::SIOCSIFFLAGS as _, &mut ifr);

            libc::close(tun_sock);
        }

        // Cache the interface index for netlink/routing lookup
        let c_name = std::ffi::CString::new("tox_master0").unwrap();
        self.interface_index = unsafe { libc::if_nametoindex(c_name.as_ptr()) as i32 };

        // Clone handles for the background reader thread
        let fd_clone = self.fd;
        let routes_clone = Arc::clone(&self.routes);

        // Spawn a background thread to continuously intercept packets coming out of the kernel stack
        std::thread::spawn(move || {
            Self::reader_loop(fd_clone, routes_clone);
        });
    }

    /// Background worker loop that blocks on `libc::read` to capture outbound kernel packets from the TUN device.
    fn reader_loop(fd: RawFd, routes: Arc<Mutex<Vec<Route>>>) {
        let mut readbuffer = [0u8; 1500];
        loop {
            let size = unsafe {
                libc::read(fd, readbuffer.as_mut_ptr() as *mut _, readbuffer.len())
            };
            if size < 0 {
                let err = io::Error::last_os_error();
                // Exit cleanly if file descriptor is closed during shutdown
                if err.raw_os_error() == Some(libc::EBADF) {
                    break;
                }
                eprintln!("Unable to read from TUN interface: {err}");
                break;
            } else if size > 0 {
                let packet_len = size as usize;
                let pi_size = std::mem::size_of::<tun_pi>();

                // Ensure the packet is large enough to contain both the TUN PI header and an IPv4 header
                if packet_len >= pi_size + 20 {
                    // Extract the destination IPv4 address (bytes 16-19 of the IPv4 header)
                    let dst_ip_bytes = &readbuffer[pi_size + 16..pi_size + 20];
                    let dst_ip = Ipv4Addr::new(
                        dst_ip_bytes[0],
                        dst_ip_bytes[1],
                        dst_ip_bytes[2],
                        dst_ip_bytes[3],
                    );

                    // Look up matching peer route in thread-safe route table
                    let matched_route = {
                        let lock = routes.lock().unwrap();
                        lock.iter().find(|r| {
                            let net_bits = u32::from(r.network);
                            let mask_bits = u32::from(r.mask);
                            (net_bits & mask_bits) == (u32::from(dst_ip) & mask_bits)
                        }).cloned()
                    };

                    if let Some(route) = matched_route {
                        // Forward packet to the specific peer route
                        Self::forward_packet_static(&route, &readbuffer[..packet_len], route.netmode);
                    } else {
                        // No route found yet for this destination IP
                        // println!("No route for destination IP: {}", dst_ip);
                    }
                }
            }
        }
    }

    /// Converts a Tox public key into a valid locally-administered MAC address
    pub fn pubkey_to_mac(pubkey: &[u8], mac: &mut [u8]) {
        if pubkey.len() >= 6 && mac.len() >= 6 {
            mac[..6].copy_from_slice(&pubkey[..6]);
            mac[0] |= 2;  // Set locally administered bit
            mac[0] &= 254; // Ensure unicast bit is clear
        }
    }

    /// Checks if a given MAC address is multicast
    pub fn mac_is_multicast(mac: &[u8]) -> bool {
        !mac.is_empty() && (mac[0] & 1) != 0
    }

    /// Finds a matching route for a given destination IP address in the local routing table
    pub fn find_route(&self, peer: Ipv4Addr) -> Option<Route> {
        let peer_bits = u32::from(peer);
        let routes = self.routes.lock().unwrap();
        for route in &*routes {
            let net_bits = u32::from(route.network);
            let mask_bits = u32::from(route.mask);
            if (net_bits & mask_bits) == (peer_bits & mask_bits) {
                return Some(route.clone());
            }
        }
        None
    }

    /// Adds a peer route to the routing table
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

        let mut routes = self.routes.lock().unwrap();
        routes.push(route);
    }

    pub fn set_peer_ip(&mut self, peer: Ipv4Addr, friend_number: i32, peer_netmode: NetMode, pubkey: &[u8]) {
        self.add_peer_route(peer, friend_number, peer_netmode, pubkey);
    }

    /// Removes all routes associated with a specific friend number (peer disconnection)
    pub fn remove_peer(&mut self, friend_number: i32) {
        let mut routes = self.routes.lock().unwrap();
        routes.retain(|r| r.friend_number != friend_number);
    }

    /// Encapsulates and forwards a packet to a specific peer via Tox custom lossy network packets
    pub fn forward_packet(&self, route: &Route, readbuffer: &[u8], netmode: NetMode) {
        Self::forward_packet_static(route, readbuffer, netmode);
    }

    /// Static helper for forwarding packets (accessible by background threads without self reference)
    fn forward_packet_static(route: &Route, readbuffer: &[u8], netmode: NetMode) {
        let mut buffer = vec![0u8; readbuffer.len() + 1];
        buffer[0] = 200; // Tox-specific VPN packet prefix identifier code

        let payload_size = if route.netmode == NetMode::Tun {
            let pi_size = std::mem::size_of::<tun_pi>();
            if readbuffer.len() < pi_size {
                return;
            }
            buffer[1..1 + pi_size].copy_from_slice(&readbuffer[..pi_size]);
            let offset = pi_size + 14;
            if readbuffer.len() < offset {
                return;
            }
            let remaining = &readbuffer[offset..];
            buffer[1 + pi_size..1 + pi_size + remaining.len()].copy_from_slice(remaining);
            pi_size + remaining.len()
        } else {
            buffer[1..1 + readbuffer.len()].copy_from_slice(readbuffer);
            readbuffer.len()
        };

        // TODO: Transmit packet via Tox custom lossy packet API using route.friend_number
        let _ = (netmode, payload_size);
    }

    /// Broadcasts a packet to all connected TAP peers
    pub fn broadcast_packet(&self, readbuffer: &[u8]) {
        let routes = self.routes.lock().unwrap();
        for route in &*routes {
            if route.netmode == NetMode::Tap {
                Self::forward_packet_static(route, readbuffer, NetMode::Tap);
            }
        }
    }

    /// Injects packets received from remote peers back into the local OS kernel via the TUN file descriptor
    pub fn send_pi_packet_to_kernel(&self, data: &[u8]) {
        if self.fd >= 0 {
            let mut write_data = data.to_vec();
            let mut size = write_data.len();

            let pi_size = std::mem::size_of::<tun_pi>();
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
