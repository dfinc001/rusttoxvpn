Remember: Gemini is AI and can make mistakes. 😃

---



# ToxVPN (Rust Port)

`rusttoxvpn` is a lightweight, peer-to-peer (P2P) virtual private network (VPN) built on top of the **Project Tox** protocol using Rust. It establishes encrypted virtual TUN network interfaces between a server and client nodes over decentralized Tox connections, without requiring traditional centralized VPN gateways.

---

> [!CAUTION]
> **Limitation Caveat:** This software currently **only supports a single server and a single client pair** at this time.

---

## Features

- **P2P Architecture:** Leverages the Tox protocol for direct, encrypted peer-to-peer communication without centralized servers.
- **TUN Interface Integration:** Creates secure virtual network interfaces (`192.168.222.1` for servers, `192.168.222.2` for clients) to route IP packets seamlessly.
- **Dynamic Interface Naming:** Automatically names TUN interfaces using the process ID (e.g., `tox_[PID]`) to completely prevent device collision conflicts.
- **Auto-Authenticated Handshakes:** 
  - **Server Mode:** Can auto-generate a secure 3-word passphrase (e.g., `light-sky-dog`) or accept a custom password. Automatically validates incoming client connection requests and assigns tunnel IPs.
  - **Client Mode:** Sends encrypted connection requests containing authentication credentials and local tunnel configuration to the target Tox ID.
- **Lossy Packet Tunneling:** Optimized fast forwarding of network packets over Tox lossy streams for minimal latency and stable 0% packet loss.
- **Thread-Safe Architecture:** Built using modern Rust concurrency primitives (`OnceLock`, `Mutex`, `AtomicBool`) for safe, robust state management.

---

## Dependencies

- `libc = "0.2"`
- `ctrlc = "3.4"`
- `hex = "0.4"`
- `rand = "0.8"`

---

## Installation & Prerequisites

Make sure you have **Rust** and **Cargo** installed on a compatible Unix-based environment (Linux/macOS) with permissions to create TUN network devices.

### Step 1: Clone the repository
```bash
git clone https://github.com/dfinc001/rusttoxvpn.git
cd rusttoxvpn

```

### Step 2: Build the project

```bash
cargo build --release

```

*(Optional)* You can create a symlink or move the compiled binary to your PATH so you can execute it globally as `toxvpn`.

---

## Usage

Because ToxVPN creates and configures a network TUN interface, it requires root privileges to run.

### 1. Running the Server Node

Start the application in server mode. If you don't supply a password via `-p`, a random 3-word passphrase will be automatically generated.

```bash
sudo toxvpn --server

```

*(Optional: specify a custom password)*

```bash
sudo toxvpn --server -p my_secure_password

```

The server will output its **Tox ID** and the **Shared Password** needed for the client to connect.

---

### 2. Running the Client Node

Connect to the server by providing the server's Tox ID (`-id`) and the matching shared password (`-p`):

```bash
sudo toxvpn -id <SERVER_TOX_ID> -p <SHARED_PASSWORD>

```

---

## Project Structure

* **`main.rs`:** Entry point, handles command-line arguments, FFI callback registrations (friend requests, connection statuses, lossy packet handlers), and the main event loop.
* **`tox_core`:** FFI bindings and management for the underlying Tox protocol instance.
* **`interface`:** Manages the TUN network interface setup and dynamic routing table.
* **`bootstrap`:** Handles bootstrap node connections and public IP discovery.

```

```
