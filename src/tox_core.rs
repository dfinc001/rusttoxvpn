use std::ffi::c_void;

// ============================================================================
// FFI Declarations & System Linkage
// ============================================================================
// We use Rust's `#[link]` attributes to bind directly against the system-installed
// C libraries (`libtoxcore` and `libsodium`) without relying on heavy wrapper crates.
#[link(name = "toxcore")]
#[link(name = "sodium")]
extern "C" {
    // Core lifecycle functions
    pub fn tox_new(options: *const ToxOptions, error: *mut u32) -> *mut c_void;
    pub fn tox_kill(tox: *mut c_void);
    pub fn tox_self_get_address(tox: *const c_void, address: *mut u8);
    pub fn tox_iteration_interval(tox: *const c_void) -> u32;
    pub fn tox_iterate(tox: *mut c_void);

    // Friend management & request functions
    pub fn tox_friend_add(
        tox: *mut c_void,
        address: *const u8,
        message: *const u8,
        length: usize,
        error: *mut u32,
    ) -> u32;

    pub fn tox_friend_add_norequest(
        tox: *mut c_void,
        public_key: *const u8,
        error: *mut u32,
    ) -> u32;

    pub fn tox_callback_friend_request(
        tox: *mut c_void,
        callback: Option<
            unsafe extern "C" fn(
                tox: *mut c_void,
                public_key: *const u8,
                message: *const u8,
                length: usize,
                user_data: *mut c_void,
            ),
        >,
    );
}

// ============================================================================
// Tox Options Configuration Structure
// ============================================================================
// `#[repr(C)]` guarantees that the memory layout matches the C library's expected
// struct layout, ensuring correct alignment and field offsets across the FFI boundary.
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
            // Zero-initialize the struct memory safely, then enable required defaults
            let mut opts: ToxOptions = std::mem::zeroed();
            opts.ipv6_enabled = true;
            opts.udp_enabled = true;
            opts
        }
    }
}

// ============================================================================
// Safe Rust Wrapper for Tox Instance (RAII Pattern)
// ============================================================================
pub struct ToxInstance {
    pub ptr: *mut c_void, // Opaque pointer to the underlying C Tox struct
}

impl ToxInstance {
    /// Initializes a new live Tox core instance with default options.
    pub fn new() -> Result<Self, String> {
        let options = ToxOptions::default();
        let mut err = 0;
        
        // FFI calls are marked `unsafe` because Rust cannot verify the memory safety 
        // or correctness of arbitrary external C functions.
        let ptr = unsafe { tox_new(&options, &mut err) };

        if ptr.is_null() {
            return Err(format!("Failed to create Tox instance, error code: {err}"));
        }

        Ok(Self { ptr })
    }

    /// Retrieves the local node's real 38-byte Tox address and converts it 
    /// into a 76-character hexadecimal string representation (the Tox ID).
    pub fn get_address_hex(&self) -> String {
        let mut address = [0u8; 38]; // TOX_ADDRESS_SIZE is exactly 38 bytes
        unsafe {
            tox_self_get_address(self.ptr, address.as_mut_ptr());
        }
        hex::encode(address)
    }
}

// ============================================================================
// Automatic Cleanup (RAII)
// ============================================================================
// When the `ToxInstance` goes out of scope, Rust automatically invokes `drop`,
// safely freeing the C-allocated memory via `tox_kill` to prevent memory leaks.
impl Drop for ToxInstance {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                tox_kill(self.ptr);
            }
        }
    }
}
