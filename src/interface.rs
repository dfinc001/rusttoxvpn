#![allow(dead_code)]
use std::io;
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};
use crate::tox_core;

/// Size of a Tox public key in bytes
pub const TOX_PUBLIC_KEY_SIZE: usize = 32;

/// Wrapper to allow sending the raw FFI Tox pointer across thread boundaries safely
struct SendPtr(*mut std::ffi::c_void);
unsafe impl Send for SendPtr {}

/// Linux TUN Packet Information (PI) header structure.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct tun_pi {
    pub flags: u16,
    pub proto: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetMode {
    Tun = 0,
    Tap = 1,
}

#[derive(Debug, Clone)]
pub struct Route {
    pub network: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub maskbits: i32,
    pub friend_number: i32,
    pub netmode: NetMode,
    pub pubkey: [u8; TOX_PUBLIC_KEY_SIZE],
}

pub struct NetworkInterface {
    pub routes: Arc<Mutex<Vec<Route>>>,
    fd: RawFd,
    my_tox: *mut std::ffi::c_void,
    interface_index: i32,
    mymac: [u8; 6],
}

impl NetworkInterface {
    pub fn new(my_tox: *mut std::ffi::c_void) -> Self {
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

    pub fn configure(&mut self, ip_in: &str, netmode: NetMode) {
        if self.fd < 0 {
            eprintln!("TUN file descriptor is invalid.");
            return;
        }

        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        ifr.ifr_ifru.ifru_flags = match netmode {
            NetMode::Tap => libc::IFF_TAP as i16,
            NetMode::Tun => (libc::IFF_TUN | libc::IFF_NO_PI) as i16, // Disable PI header for simpler raw IP handling
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
            eprintln!("Error configuring TUNSETIFF");
            std::process::exit(-1);
        }

        let tun_sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if tun_sock < 0 {
            return;
        }

        unsafe {
            ifr.ifr_ifru.ifru_mtu = 1200;
            libc::ioctl(tun_sock, libc::SIOCSIFMTU as _, &mut ifr);
        }

        let ip_addr: Ipv4Addr = ip_in.parse().unwrap_or(Ipv4Addr::new(192, 168, 222, 1));

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

            let netmask = Ipv4Addr::new(255, 255, 255, 0);
            addr.sin_addr.s_addr = u32::from(netmask).to_be();
            std::ptr::copy_nonoverlapping(
                &addr as *const _ as *const u8,
                &mut ifr.ifr_ifru.ifru_netmask as *mut _ as *mut u8,
                std::mem::size_of::<libc::sockaddr_in>(),
            );
            libc::ioctl(tun_sock, libc::SIOCSIFNETMASK as _, &mut ifr);

            libc::ioctl(tun_sock, libc::SIOCGIFFLAGS as _, &mut ifr);
            ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as i16;
            libc::ioctl(tun_sock, libc::SIOCSIFFLAGS as _, &mut ifr);

            libc::close(tun_sock);
        }

        let c_name = std::ffi::CString::new("tox_master0").unwrap();
        self.interface_index = unsafe { libc::if_nametoindex(c_name.as_ptr()) as i32 };

        let fd_clone = self.fd;
        let routes_clone = Arc::clone(&self.routes);
        let tox_ptr = SendPtr(self.my_tox);

        std::thread::spawn(move || {
            Self::reader_loop(fd_clone, routes_clone, tox_ptr);
        });
    }

    fn reader_loop(fd: RawFd, routes: Arc<Mutex<Vec<Route>>>, tox_ptr: SendPtr) {
        let mut readbuffer = [0u8; 1500];
        loop {
            let size = unsafe {
                libc::read(fd, readbuffer.as_mut_ptr() as *mut _, readbuffer.len())
            };
            if size < 0 {
                break;
            } else if size > 20 {
                let packet_len = size as usize;
                // With IFF_NO_PI, the packet starts immediately with the IPv4 header
                let dst_ip_bytes = &readbuffer[16..20];
                let dst_ip = Ipv4Addr::new(
                    dst_ip_bytes[0],
                    dst_ip_bytes[1],
                    dst_ip_bytes[2],
                    dst_ip_bytes[3],
                );

                let matched_route = {
                    let lock = routes.lock().unwrap();
                    lock.iter().find(|r| {
                        let net_bits = u32::from(r.network);
                        let mask_bits = u32::from(r.mask);
                        (net_bits & mask_bits) == (u32::from(dst_ip) & mask_bits)
                    }).cloned()
                };

                if let Some(route) = matched_route {
                    Self::forward_packet_static(tox_ptr.0, &route, &readbuffer[..packet_len], route.netmode);
                }
            }
        }
    }

    pub fn pubkey_to_mac(pubkey: &[u8], mac: &mut [u8]) {
        if pubkey.len() >= 6 && mac.len() >= 6 {
            mac[..6].copy_from_slice(&pubkey[..6]);
            mac[0] |= 2;
            mac[0] &= 254;
        }
    }

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

    fn forward_packet_static(tox: *mut std::ffi::c_void, route: &Route, readbuffer: &[u8], _netmode: NetMode) {
        // Prefix with VPN packet identifier code (200)
        let mut buffer = vec![0u8; readbuffer.len() + 1];
        buffer[0] = 200;
        buffer[1..].copy_from_slice(readbuffer);

        let mut err = 0;
        let success = unsafe {
            tox_core::tox_friend_send_lossy_packet(
                tox,
                route.friend_number as u32,
                buffer.as_ptr(),
                buffer.len(),
                &mut err,
            )
        };

        if !success {
            eprintln!("Failed to send lossy packet to friend {}, error code: {err}", route.friend_number);
        }
    }

    pub fn send_pi_packet_to_kernel(&self, data: &[u8]) {
        if self.fd >= 0 {
            let ret = unsafe { libc::write(self.fd, data.as_ptr() as *const _, data.len()) };
            if ret < 0 || ret as usize != data.len() {
                eprintln!("Failed to write packet to TUN interface");
            }
        }
    }
}
