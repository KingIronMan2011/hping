//! Local IP and interface discovery.
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

/// Determines the local IPv4 address that would be used to route to `dst`.
pub fn get_local_ip_for_dest(dst: Ipv4Addr) -> std::io::Result<Ipv4Addr> {
    let dummy = UdpSocket::bind("0.0.0.0:0")?;
    dummy.connect(SocketAddr::from((dst, 80)))?;
    if let SocketAddr::V4(addr) = dummy.local_addr()? {
        Ok(*addr.ip())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "Could not determine local IPv4 address",
        ))
    }
}
