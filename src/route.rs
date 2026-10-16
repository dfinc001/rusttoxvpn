use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;
use std::io;

// --- Linux Specific Implementation ---

#[cfg(target_os = "linux")]
static mut NETLINK_SOCKET: RawFd = -1;

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rtmsg {
    pub rtm_family: u8,
    pub rtm_dst_len: u8,
    pub rtm_src_len: u8,
    pub rtm_tos: u8,
    pub rtm_table: u8,
    pub rtm_protocol: u8,
    pub rtm_scope: u8,
    pub rtm_type: u8,
    pub rtm_flags: u32,
}

/// Initializes the system routing environment and tables
pub fn route_init() {
    #[cfg(target_os = "linux")]
    unsafe {
        NETLINK_SOCKET = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM,
            libc::NETLINK_ROUTE,
        );
        if NETLINK_SOCKET < 0 {
            eprintln!("Failed to create netlink socket: {}", io::Error::last_os_error());
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        println!("Initializing system routing tables...");
    }
}

#[cfg(target_os = "linux")]
struct NetlinkRouteRequest {
    nlh: libc::nlmsghdr,
    rtm: rtmsg,
    buffer: [u8; 512],
    offset: usize,
}

#[cfg(target_os = "linux")]
impl NetlinkRouteRequest {
    fn new(destination: Ipv4Addr, ifindex: i32, gateway: Option<Ipv4Addr>) -> Self {
        let mut req = Self {
            nlh: unsafe { std::mem::zeroed() },
            rtm: unsafe { std::mem::zeroed() },
            buffer: [0u8; 512],
            offset: 0,
        };

        req.rtm.rtm_family = libc::AF_INET as u8;
        req.rtm.rtm_table = libc::RT_TABLE_MAIN as u8;
        req.rtm.rtm_protocol = libc::RTPROT_STATIC as u8;
        req.rtm.rtm_scope = libc::RT_SCOPE_UNIVERSE as u8;
        req.rtm.rtm_type = libc::RTN_UNICAST as u8;
        req.rtm.rtm_dst_len = 32;

        req.add_attr(libc::RTA_DST, &destination.octets());

        if let Some(gw) = gateway {
            req.add_attr(libc::RTA_GATEWAY, &gw.octets());
        }

        req.add_attr(libc::RTA_OIF, &ifindex.to_ne_bytes());

        let payload_len = std::mem::size_of::<rtmsg>() + req.offset;
        req.nlh.nlmsg_len = libc::NLMSG_LENGTH(payload_len) as u32;
        req.nlh.nlmsg_flags = (libc::NLM_F_REQUEST | libc::NLM_F_CREATE) as u16;
        req.nlh.nlmsg_type = libc::RTM_NEWROUTE as u16;

        req
    }

    fn add_attr(&mut self, rta_type: u16, data: &[u8]) {
        let rta_len = (std::mem::size_of::<libc::rtattr>() + data.len()) as u16;
        let attr = libc::rtattr {
            rta_len,
            rta_type,
        };

        unsafe {
            let attr_ptr = self.buffer[self.offset..].as_mut_ptr() as *mut libc::rtattr;
            std::ptr::write(attr_ptr, attr);

            let data_ptr = self.buffer[self.offset + std::mem::size_of::<libc::rtattr>()..].as_mut_ptr();
            std::ptr::copy_nonoverlapping(data.as_ptr(), data_ptr, data.len());
        }

        let aligned_len = (rta_len as usize + 3) & !3;
        self.offset += aligned_len;
    }

    fn send(&self) {
        unsafe {
            if NETLINK_SOCKET < 0 {
                return;
            }

            let mut sa: libc::sockaddr_nl = std::mem::zeroed();
            sa.nl_family = libc::AF_NETLINK as u16;

            let mut msg_bytes = Vec::new();
            msg_bytes.extend_from_slice(std::slice::from_raw_parts(
                &self.nlh as *const _ as *const u8,
                std::mem::size_of::<libc::nlmsghdr>(),
            ));
            msg_bytes.extend_from_slice(std::slice::from_raw_parts(
                &self.rtm as *const _ as *const u8,
                std::mem::size_of::<rtmsg>(),
            ));
            msg_bytes.extend_from_slice(&self.buffer[..self.offset]);

            let iov = libc::iovec {
                iov_base: msg_bytes.as_ptr() as *mut _,
                iov_len: msg_bytes.len(),
            };

            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_name = &mut sa as *mut _ as *mut _;
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as u32;
            msg.msg_iov = &iov as *const _ as *mut _;
            msg.msg_iovlen = 1;

            let res = libc::sendmsg(NETLINK_SOCKET, &msg, 0);
            if res < 0 {
                eprintln!("Route error: {}", io::Error::last_os_error());
            }
        }
    }
}

/// Adds a routing entry with a specified gateway through a given network interface index
pub fn system_route_single(ifindex: i32, destination: Ipv4Addr, gateway: &str) {
    #[cfg(target_os = "linux")]
    {
        if let Ok(gw_ip) = gateway.parse::<Ipv4Addr>() {
            let req = NetlinkRouteRequest::new(destination, ifindex, Some(gw_ip));
            req.send();
        } else {
            eprintln!("Invalid gateway IP address: {gateway}");
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (ifindex, destination, gateway);
    }
}

/// Adds a direct host route for a peer through a given network interface index
pub fn system_route_direct(ifindex: i32, destination: Ipv4Addr) {
    #[cfg(target_os = "linux")]
    {
        let req = NetlinkRouteRequest::new(destination, ifindex, None);
        req.send();
    }

    #[cfg(not(target_os = "linux"))]
    {
        println!("Adding direct route for {destination} on interface index {ifindex}");
    }
}
