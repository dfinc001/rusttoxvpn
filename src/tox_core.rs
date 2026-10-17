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
    pub fn tox_options_new(error: *mut u32) -> *mut c_void;
    pub fn tox_options_free(options: *mut c_void);
    pub fn tox_options_set_ipv6_enabled(options: *mut c_void, enabled: bool);
    pub fn tox_options_set_udp_enabled(options: *mut c_void, enabled: bool);
    pub fn tox_options_set_tcp_port(options: *mut c_void, port: u16);
    pub fn tox_new(options: *const c_void, error: *mut u32) -> *mut c_void;
    pub fn tox_kill(tox: *mut c_void);
    pub fn tox_self_get_address(tox: *const c_void, address: *mut u8);
    pub fn tox_iteration_interval(tox: *const c_void) -> u32;
    pub fn tox_iterate(tox: *mut c_void);

    // DHT Bootstrap function
    pub fn tox_bootstrap(
        tox: *mut c_void,
        host: *const i8,
        port: u16,
        public_key: *const u8,
        error: *mut u32,
    ) -> bool;

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

    // Connection status & lossy packet forwarding FFI bindings
    pub fn tox_callback_friend_connection_status(
        tox: *mut c_void,
        callback: ToxFriendConnectionStatusCb,
    );

    pub fn tox_callback_friend_lossy_packet(
        tox: *mut c_void,
        callback: ToxFriendLossyPacketCb,
    );

    pub fn tox_friend_send_lossy_packet(
        tox: *mut c_void,
        friend_number: u32,
        data: *const u8,
        length: usize,
        error: *mut u32,
    ) -> bool;
}

// ============================================================================
// Callback Type Definitions for FFI Signatures
// ============================================================================
pub type ToxFriendConnectionStatusCb = Option<
    unsafe extern "C" fn(
        tox: *mut c_void,
        friend_number: u32,
        connection_status: u32,
        user_data: *mut c_void,
    ),
>;

pub type ToxFriendLossyPacketCb = Option<
    unsafe extern "C" fn(
        tox: *mut c_void,
        friend_number: u32,
        data: *const u8,
        length: usize,
        user_data: *mut c_void,
    ),
>;



// ============================================================================
// Safe Rust Wrapper for Tox Instance (RAII Pattern)
// ============================================================================
pub struct ToxInstance {
    pub ptr: *mut c_void, // Opaque pointer to the underlying C Tox struct
}

impl ToxInstance {
    /// Initializes a new live Tox core instance with default options.
    pub fn new() -> Result<Self, String> {
        let mut options_error = 0;
        let options = unsafe { tox_options_new(&mut options_error) };

        if options.is_null() {
            return Err(format!("tox_options_new failed: {options_error}"));
        }

        unsafe {
            tox_options_set_ipv6_enabled(options, true);
            tox_options_set_udp_enabled(options, true);
            tox_options_set_tcp_port(options, 33445);
        }

        let mut err = 0;
        let ptr = unsafe { tox_new(options, &mut err) };
        unsafe { tox_options_free(options) };

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
