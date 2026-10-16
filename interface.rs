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
    /// Opens the Linux TUN/TAP device driver (/dev/net/tun)
    pub fn new(my_tox: *mut std::ffi::c_void) -> Self {
        let fd = unsafe { libc::open(b"/dev/net/tun\0".as_ptr() as *const _, libc::O_RDWR) };
        if fd < 0 {
            eprintln!("Unable to open /dev/net/tun");
        }

        Self {
            routes: Vec::new(),
            fd,
            my_tox,
            interface_index: 0,
            mymac: [0u8; 6],
        }
    }

    /// Configures the TUN/TAP interface, sets MAC addresses, MTU, IP addresses, and launches the reader thread
    pub fn configure(&mut self, ip_in: &str, netmode: NetMode) {
        if self.fd < 0 {
            eprintln!("TUN file descriptor is invalid.");
            return;
        }

        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        
        ifr.ifr_ifru.ifru_flags = match netmode {
            NetMode::Tap => libc::IFF_TAP as i16,
            NetMode::Tun => libc::IFF_TUN as i16,
        };

        let name = b"tox_master0\0";
        unsafe {
            std::ptr::copy_nonoverlapping(
                name.as_ptr() as *const i8,
                ifr.ifr_name.as_mut_ptr(),
                name.len(),
            );
        }

        let err = unsafe { libc::ioctl(self.fd, libc::TUNSETIFF as _, &mut ifr) };
        if err < 0 {
            let errno = unsafe { *libc::__errno_location() };
            if errno == libc::EPERM {
                eprintln!("No permission to create TUN device (run as root)");
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

        // Fetch Tox public key to generate hardware MAC address
        let mut pubkey = [0u8; TOX_PUBLIC_KEY_SIZE];
        // FFI placeholder: tox_self_get_public_key(self.my_tox, pubkey.as_mut_ptr());

        Self::pubkey_to_mac(&pubkey, &mut self.mymac);

        let tun_sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if tun_sock < 0 {
            eprintln!("Error while creating configuration socket");
            return;
        }

        unsafe {
            ifr.ifr_ifru.ifru_mtu = 1200;
            libc::ioctl(tun_sock, libc::SIOCSIFMTU as _, &mut ifr);
        }

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

            let dst_ip = Ipv4Addr::new(10, 123, 123, 123);
            addr.sin_addr.s_addr = u32::from(dst_ip).to_be();
            std::ptr::copy_nonoverlapping(
                &addr as *const _ as *const u8,
                &mut ifr.ifr_ifru.ifru_dstaddr as *mut _ as *mut u8,
                std::mem::size_of::<libc::sockaddr_in>(),
            );
            libc::ioctl(tun_sock, libc::SIOCSIFDSTADDR as _, &mut ifr);

            libc::ioctl(tun_sock, libc::SIOCGIFFLAGS as _, &mut ifr);
            ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as i16;
            libc::ioctl(tun_sock, libc::SIOCSIFFLAGS as _, &mut ifr);

            libc::close(tun_sock);
        }

        let c_name = std::ffi::CString::new("tox_master0").unwrap();
        self.interface_index = unsafe { libc::if_nametoindex(c_name.as_ptr()) as i32 };

        let fd_clone = self.fd;
        std::thread::spawn(move || {
            Self::reader_loop(fd_clone);
        });
    }

    fn reader_loop(fd: RawFd) {
        let mut readbuffer = [0u8; 1500];
        loop {
            let size = unsafe {
                libc::read(fd, readbuffer.as_mut_ptr() as *mut _, readbuffer.len())
            };
            if size < 0 {
                let err = io::Error::last_os_error();
                eprintln!("Unable to read from TUN interface: {err}");
                break;
            } else if size > 0 {
                // TODO: Handle incoming packet data
            }
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
            let pi_size = std::mem::size_of::<libc::tun_pi>();
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
