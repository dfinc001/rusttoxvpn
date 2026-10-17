#![allow(dead_code)]
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{self, Receiver, Sender};

pub const TOX_PUBLIC_KEY_SIZE: usize = 32;

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

pub struct OutgoingPacket {
    pub friend_number: u32,
    pub data: Vec<u8>,
}

pub struct NetworkInterface {
    pub routes: Arc<Mutex<Vec<Route>>>,
    pub fd: RawFd,
    pub rx_channel: Receiver<OutgoingPacket>,
    tx_channel: Sender<OutgoingPacket>,
    interface_index: i32,
}

impl NetworkInterface {
    pub fn new(_my_tox: *mut std::ffi::c_void) -> Self {
        let fd = unsafe { libc::open(b"/dev/net/tun\0".as_ptr() as *const _, libc::O_RDWR) };
        if fd < 0 {
            eprintln!("Unable to open /dev/net/tun");
        }

        let (tx_channel, rx_channel) = mpsc::channel();

        Self {
            routes: Arc::new(Mutex::new(Vec::new())),
            fd,
            rx_channel,
            tx_channel,
            interface_index: 0,
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
            NetMode::Tun => (libc::IFF_TUN | libc::IFF_NO_PI) as i16,
        };

        // Use dynamic/unique interface name based on PID to prevent collisions
        let iface_name = format!("tox_{}\0", std::process::id());
        let name_bytes = iface_name.as_bytes();
        if name_bytes.len() > libc::IFNAMSIZ {
            eprintln!("Interface name too long.");
            std::process::exit(-1);
        }

        unsafe {
            std::ptr::copy_nonoverlapping(
                name_bytes.as_ptr() as *const i8,
                ifr.ifr_name.as_mut_ptr(),
                name_bytes.len(),
            );
        }

        let err = unsafe { libc::ioctl(self.fd, libc::TUNSETIFF as _, &mut ifr) };
        let name_cstring = std::ffi::CString::new(&name_bytes[..name_bytes.len() - 1]).unwrap();
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

        self.interface_index = unsafe { libc::if_nametoindex(name_cstring.as_ptr()) as i32 };

        let fd_clone = self.fd;
        let routes_clone = Arc::clone(&self.routes);
        let tx_clone = self.tx_channel.clone();

        std::thread::spawn(move || {
            Self::reader_loop(fd_clone, routes_clone, tx_clone);
        });
    }

    fn reader_loop(fd: RawFd, routes: Arc<Mutex<Vec<Route>>>, tx: Sender<OutgoingPacket>) {
        let mut readbuffer = [0u8; 1500];
        loop {
            let size = unsafe {
                libc::read(fd, readbuffer.as_mut_ptr() as *mut _, readbuffer.len())
            };
            if size < 0 {
                break;
            } else if size >= 20 {
                let packet_len = size as usize;
                
                // Validate IPv4 version header (top nibble of byte 0 should be 4)
                let version = readbuffer[0] >> 4;
                if version != 4 {
                    continue;
                }

                let dst_ip_bytes = &readbuffer[16..20];
                let dst_ip = Ipv4Addr::new(
                    dst_ip_bytes[0],
                    dst_ip_bytes[1],
                    dst_ip_bytes[2],
                    dst_ip_bytes[3],
                );

                let matched_route = {
                    let lock = match routes.lock() {
                        Ok(l) => l,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    lock.iter().find(|r| {
                        let net_bits = u32::from(r.network);
                        let mask_bits = u32::from(r.mask);
                        (net_bits & mask_bits) == (u32::from(dst_ip) & mask_bits)
                    }).cloned()
                };

                if let Some(route) = matched_route {
                    let mut buffer = vec![0u8; packet_len + 1];
                    buffer[0] = 200;
                    buffer[1..].copy_from_slice(&readbuffer[..packet_len]);

                    let _ = tx.send(OutgoingPacket {
                        friend_number: route.friend_number as u32,
                        data: buffer,
                    });
                }
            }
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
