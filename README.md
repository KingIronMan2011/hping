# hping

A command-line oriented TCP/IP packet assembler and analyzer.

**Author**: Salvatore Sanfilippo <antirez@invece.org>  
**License**: [GPL-2.0](LICENSE.md)

---

## Description

`hping` is a network tool able to send custom TCP/IP packets and to display target replies like `ping` does with ICMP replies. It handles fragmentation, arbitrary packet sizes, and arbitrary packet contents via the command-line interface.

Since version 3, `hping` implements scripting capabilities (see `docs/API.txt` for details).

### Common Use Cases

- **Firewall & ACL Testing**: Test filtering rules and security appliances.
- **Advanced Traceroute**: Traceroute-like path discovery over any supported protocol (TCP, UDP, ICMP, Raw IP).
- **Firewalking**: Determine firewall rules and open ports behind filtering gateways.
- **Remote OS Fingerprinting**: Inspect TCP/IP stack behavior to identify remote operating systems.
- **Port Scanning**: High-performance port scanning via the `--scan` option.
- **TCP/IP Stack Auditing**: Audit sequence numbers, timestamp options, and fragmentation handling.
- **Network Learning & Education**: A didactic tool for exploring the TCP/IP protocol suite in depth.

---

## Scripting Capabilities

Using Tcl/Tk scripting, complex packet sequences, test suites, and protocol simulations can be authored.

Example scripts are available under the [`lib/`](lib/) directory. To run an example script:

```bash
hping exec lib/<ScriptName>.htcl [arguments]
```

---

## Documentation

- Check the API reference in `docs/API.txt`.
- Manual page: `docs/hping3.8` (or `man hping` once installed).
- Additional guides and technical notes are located in the [`docs/`](docs/) directory.

---

## Requirements

- Unix-like operating system (Linux, BSD, macOS, Solaris)
- GCC or Clang
- `libpcap` library and development headers
- `tcl` development headers (optional, for scripting support)
- Root / superuser privileges (required for raw sockets)

---

## Installation

See [`INSTALL.md`](INSTALL.md) for full compilation and installation instructions.

```bash
./configure
make
sudo make install
```
