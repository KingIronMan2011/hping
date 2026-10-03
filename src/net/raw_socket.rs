//! Low-level Raw Socket sender implementation.
use std::net::{Ipv4Addr, SocketAddrV4};
#[cfg(target_os = "linux")]
use socket2::Protocol;
use socket2::{Domain, Socket, Type};

pub struct RawSocketSender {
    socket: Socket,
}

impl RawSocketSender {
    /// Creates a new Raw IPv4 socket with IP_HDRINCL enabled.
    pub fn new(interface: Option<&str>) -> std::io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let sock = Socket::new(
                Domain::IPV4,
                Type::RAW,
                Some(Protocol::from(libc::IPPROTO_RAW)),
            )?;

            sock.set_header_included_v4(true)?;
            sock.set_broadcast(true)?;

            if let Some(iface) = interface {
                sock.bind_device(Some(iface.as_bytes()))?;
            }

            Ok(Self { socket: sock })
        }

        #[cfg(not(target_os = "linux"))]
        {
            // Fallback for non-Linux targets (e.g. Windows or BSD)
            let sock = Socket::new(Domain::IPV4, Type::RAW, None)?;
            let _ = sock.set_header_included_v4(true);
            let _ = sock.set_broadcast(true);
            let _ = interface;
            Ok(Self { socket: sock })
        }
    }

    /// Sends a raw IPv4 packet buffer to the destination IP address.
    pub fn send_packet(&self, packet: &[u8], dst: Ipv4Addr) -> std::io::Result<usize> {
        let dest_addr = SocketAddrV4::new(dst, 0);
        self.socket.send_to(packet, &dest_addr.into())
    }
}
