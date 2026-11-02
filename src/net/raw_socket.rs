//! Low-level Raw Socket and Packet sender implementation.
use std::net::Ipv4Addr;
#[cfg(not(windows))]
use std::net::SocketAddrV4;

#[cfg(target_os = "linux")]
use socket2::Protocol;
#[cfg(not(windows))]
use socket2::{Domain, Socket, Type};

#[cfg(windows)]
use crate::net::windows::{get_best_route_info, get_windows_adapters, PcapT, WinRouteInfo, Wpcap, DLT_NULL};
#[cfg(windows)]
use std::sync::Arc;

pub struct RawSocketSender {
    #[cfg(not(windows))]
    socket: Socket,

    #[cfg(windows)]
    wpcap: Arc<Wpcap>,
    #[cfg(windows)]
    handle: *mut PcapT,
    #[cfg(windows)]
    route_info: WinRouteInfo,
    #[cfg(windows)]
    datalink_type: std::ffi::c_int,
}

#[cfg(windows)]
unsafe impl Send for RawSocketSender {}
#[cfg(windows)]
unsafe impl Sync for RawSocketSender {}

#[cfg(windows)]
impl Drop for RawSocketSender {
    fn drop(&mut self) {
        self.wpcap.close(self.handle);
    }
}

impl RawSocketSender {
    /// Creates a new packet sender. On Linux/Unix, uses raw sockets. On Windows, uses Npcap / WinPcap.
    pub fn new(interface: Option<&str>, dst_ip: Ipv4Addr) -> std::io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let _ = dst_ip;
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

        #[cfg(all(not(target_os = "linux"), not(windows)))]
        {
            let _ = (dst_ip, interface);
            let sock = Socket::new(Domain::IPV4, Type::RAW, None)?;
            let _ = sock.set_header_included_v4(true);
            let _ = sock.set_broadcast(true);
            Ok(Self { socket: sock })
        }

        #[cfg(windows)]
        {
            let wpcap = Wpcap::load().map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::NotConnected, e)
            })?;

            let mut route_info = get_best_route_info(dst_ip).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::NotFound, e)
            })?;

            // If user specified an interface name, check if it matches an adapter friendly name or GUID
            let dev_name = if let Some(iface) = interface {
                let adapters = get_windows_adapters();
                if let Some(a) = adapters.iter().find(|a| {
                    a.friendly_name.eq_ignore_ascii_case(iface)
                        || a.adapter_name.eq_ignore_ascii_case(iface)
                }) {
                    route_info.npcap_device_name = format!(r"\Device\NPF_{}", a.adapter_name);
                    route_info.local_mac = a.mac_addr;
                    route_info.if_index = a.if_index;
                    if !a.ipv4_addrs.is_empty() {
                        route_info.src_ip = a.ipv4_addrs[0];
                    }
                    route_info.npcap_device_name.clone()
                } else if iface.starts_with(r"\Device\NPF_") {
                    iface.to_string()
                } else {
                    format!(r"\Device\NPF_{}", iface)
                }
            } else {
                route_info.npcap_device_name.clone()
            };

            let handle = wpcap.open_live(&dev_name, 65536, true, 50).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::Other, e)
            })?;

            let datalink_type = wpcap.datalink(handle);

            Ok(Self {
                wpcap,
                handle,
                route_info,
                datalink_type,
            })
        }
    }

    /// Sends a raw IPv4 packet buffer to the destination IP address.
    pub fn send_packet(&self, packet: &[u8], dst: Ipv4Addr) -> std::io::Result<usize> {
        #[cfg(not(windows))]
        {
            let dest_addr = SocketAddrV4::new(dst, 0);
            self.socket.send_to(packet, &dest_addr.into())
        }

        #[cfg(windows)]
        {
            let _ = dst;
            if self.datalink_type == DLT_NULL {
                // BSD / Npcap loopback encapsulation: 4 bytes family (AF_INET = 2 in host byte order)
                let mut frame = Vec::with_capacity(4 + packet.len());
                frame.extend_from_slice(&(2u32).to_ne_bytes());
                frame.extend_from_slice(packet);
                self.wpcap.sendpacket(self.handle, &frame).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::Other, e)
                })?;
            } else {
                // Ethernet encapsulation (DLT_EN10MB): 14 bytes (Dst MAC 6B + Src MAC 6B + EtherType 2B)
                let mut frame = Vec::with_capacity(14 + packet.len());
                frame.extend_from_slice(&self.route_info.target_mac);
                frame.extend_from_slice(&self.route_info.local_mac);
                frame.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4 EtherType
                frame.extend_from_slice(packet);

                self.wpcap.sendpacket(self.handle, &frame).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::Other, e)
                })?;
            }
            Ok(packet.len())
        }
    }
}
