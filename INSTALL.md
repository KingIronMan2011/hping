# Installation

## Prerequisites

To build and run `hping` in Rust, ensure you have:

- Rust and Cargo (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- Linux with root privileges or `CAP_NET_RAW` capability:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/hping
  ```

## Compilation

```bash
cargo build --release
```

To install system-wide:

```bash
cargo install --path .
```
