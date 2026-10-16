use std::time::Instant;

/// Networking mode for the VPN interface (corresponds to MODE_TUN / MODE_TAP)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetMode {
    Tun,
    Tap,
}

/// Represents a bootstrap node used to connect to the Tox network
#[derive(Debug, Clone)]
pub struct BootstrapNode {
    pub ipv4: String,
    pub pubkey: String,
    pub port: u16,
}

impl BootstrapNode {
    /// Creates a new bootstrap node instance
    pub fn new(ipv4: impl Into<String>, port: u16, pubkey: impl Into<String>) -> Self {
        Self {
            ipv4: ipv4.into(),
            pubkey: pubkey.into(),
            port,
        }
    }
}

/// Opaque placeholder for the socket listener (replaces raw C++ pointer `SocketListener*`)
pub struct SocketListener {
    // Listener fields go here
}

/// Core state container for the ToxVPN application
pub struct ToxVpnCore {
    pub listener: Option<Box<SocketListener>>,
    pub auto_friends: Vec<String>,
    pub nodes: Vec<BootstrapNode>,
    pub last_bootstrap: Instant,
}

impl Default for ToxVpnCore {
    fn default() -> Self {
        Self {
            listener: None,
            auto_friends: Vec::new(),
            nodes: Vec::new(),
            last_bootstrap: Instant::now(),
        }
    }
}

// Opaque placeholder for the Tox core type from the C library bindings
pub struct Tox;

// --- Function Declarations / Interfaces ---

/// Saves the current Tox state. Returns true on success.
pub fn save_state(tox: &mut Tox) -> bool {
    // TODO: Implement state saving logic
    let _ = tox;
    true
}

/// Performs the bootstrapping process using configured nodes
pub fn do_bootstrap(tox: &mut Tox, toxvpn: &mut ToxVpnCore) {
    // TODO: Implement bootstrap logic using toxvpn.nodes
    let _ = (tox, toxvpn);
}

/// Converts a byte array into a hexadecimal string representation
pub fn to_hex(dest: &mut String, src: &[u8]) {
    *dest = hex::encode(src); // Highly optimized using a standard crate like `hex`
}

/// Converts a hexadecimal string back into binary byte data
pub fn hex_string_to_bin(hex_string: &str, ret: &mut [u8]) -> Result<(), &'static str> {
    let decoded = hex::decode(hex_string).map_err(|_| "Invalid hex string")?;
    if decoded.len() > ret.len() {
        return Err("Destination buffer too small");
    }
    ret[..decoded.len()].copy_from_slice(&decoded);
    Ok(())
}
