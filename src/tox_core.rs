use std::ffi::c_void;

// Link against system libtoxcore and libsodium
#[link(name = "toxcore")]
#[link(name = "sodium")]
extern "C" {
    pub fn tox_new(options: *const ToxOptions, error: *mut u32) -> *mut c_void;
    pub fn tox_kill(tox: *mut c_void);
    pub fn tox_self_get_address(tox: *const c_void, address: *mut u8);
    pub fn tox_iteration_interval(tox: *const c_void) -> u32;
    pub fn tox_iterate(tox: *mut c_void);
}

#[repr(C)]
pub struct ToxOptions {
    pub ipv6_enabled: bool,
    pub udp_enabled: bool,
    pub proxy_type: u8,
    pub proxy_host: *const i8,
    pub proxy_port: u16,
    pub start_port: u16,
    pub end_port: u16,
    pub tcp_port: u16,
    pub savedata_type: u8,
    pub savedata_data: *const u8,
    pub savedata_length: usize,
}

impl Default for ToxOptions {
    fn default() -> Self {
        unsafe {
            let mut opts: ToxOptions = std::mem::zeroed();
            opts.ipv6_enabled = true;
            opts.udp_enabled = true;
            opts
        }
    }
}

pub struct ToxInstance {
    pub ptr: *mut c_void,
}

impl ToxInstance {
    pub fn new() -> Result<Self, String> {
        let options = ToxOptions::default();
        let mut err = 0;
        let ptr = unsafe { tox_new(&options, &mut err) };

        if ptr.is_null() {
            return Err(format!("Failed to create Tox instance, error code: {err}"));
        }

        Ok(Self { ptr })
    }

    /// Gets the real 38-byte Tox address (expressed as a 76-character hex string)
    pub fn get_address_hex(&self) -> String {
        let mut address = [0u8; 38]; // TOX_ADDRESS_SIZE is 38 bytes
        unsafe {
            tox_self_get_address(self.ptr, address.as_mut_ptr());
        }
        hex::encode(address)
    }
}

impl Drop for ToxInstance {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                tox_kill(self.ptr);
            }
        }
    }
}
