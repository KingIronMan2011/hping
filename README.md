# hping (Rust)

A high-performance, command-line oriented TCP/IP packet assembler and analyzer rewritten in pure, safe Rust.

**Original Author**: Salvatore Sanfilippo <antirez@invece.org>  
**License**: [GPL-2.0](LICENSE.md)

---

## Description

`hping` is a network tool capable of sending custom TCP/IP packets and displaying target replies, similar to `ping` but with full control over TCP, UDP, ICMP, and RAW IP protocols. It supports MTU fragmentation, custom packet sizes, arbitrary payload signatures/files, TCP flag manipulation, traceroute path discovery, high-throughput flooding, and multi-port scanning.

### Core Capabilities

- **TCP / UDP / ICMP / Raw IP Ping**: Send custom probes and analyze responses with microsecond-level RTT tracking.
- **Port Scanning (`--scan`)**: High-performance multi-port scanning across port lists and ranges (e.g. `--scan 1-1024,8080 -S target`).
- **Advanced Traceroute (`--traceroute`)**: Path discovery over TCP, UDP, or ICMP, extracting router hops from ICMP Time Exceeded packets with reverse DNS and per-hop RTT.
- **Packet Flooding (`--flood`)**: Ultra-high-speed packet generation for firewall stress testing and bandwidth saturation without waiting for replies.
- **Packet Crafting**: Bit-level control over IP headers (TTL, ID, TOS, DF/MF flags, fragmentation offset, virtual MTU) and TCP headers (flags SYN/ACK/FIN/RST/PSH/URG/XMAS/YMAS, sequence/ack numbers, window size, fake data offset, TCP timestamp option).
- **Inspection & Sniffing (`--listen`, `--dump`, `--print`)**: Passive signature matching and hex/ASCII packet inspection.

---

## Requirements & Building

- Rust toolchain (version 1.80+ or 2021 edition)
- Root / superuser / `CAP_NET_RAW` privileges on Linux (required for raw sockets and `AF_PACKET`)

### Build Instructions

```bash
cargo build --release
```

The optimized binary will be created at:

```bash
./target/release/hping
```

### Running Tests

```bash
cargo test
```

---

## Usage Examples

```bash
# TCP SYN ping to port 80 (default mode)
sudo ./target/release/hping example.com -p 80 -S

# ICMP ping with custom packet count
sudo ./target/release/hping example.com --icmp -c 5

# UDP ping
sudo ./target/release/hping example.com --udp -p 53

# Advanced TCP traceroute to port 443
sudo ./target/release/hping example.com --traceroute -p 443 -S

# Multi-port SYN scan
sudo ./target/release/hping example.com --scan 21,22,80,443,8080 -S

# High-speed packet flood
sudo ./target/release/hping example.com --flood -p 80 -S --rand-source

# Fragmented packets with virtual MTU of 64 bytes
sudo ./target/release/hping example.com -d 200 --frag -m 64
```
