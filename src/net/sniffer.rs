//! Packet sniffer using native Linux AF_PACKET raw sockets or Npcap on Windows.
#[cfg(not(windows))]
use std::mem::MaybeUninit;

#[cfg(target_os = "linux")]
use socket2::Protocol;
#[cfg(not(windows))]
use socket2::{Domain, Socket, Type};

#[cfg(windows)]
use crate::net::windows::{get_best_route_info, get_windows_adapters, PcapT, Wpcap, DLT_NULL};
#[cfg(windows)]
use std::net::Ipv4Addr;
#[cfg(windows)]
use std::sync::Arc;

pub struct PacketSniffer {
    #[cfg(not(windows))]
    socket: Socket,
    #[cfg(not(windows))]
    buffer: Vec<u8>,

    #[cfg(windows)]
    wpcap: Arc<Wpcap>,
    #[cfg(windows)]
    handle: *mut PcapT,
    #[cfg(windows)]
    datalink_type: std::ffi::c_int,
    #[cfg(windows)]
    current_packet: Vec<u8>,
}

#[cfg(windows)]
unsafe impl Send for PacketSniffer {}
#[cfg(windows)]
unsafe impl Sync for PacketSniffer {}

#[cfg(windows)]
impl Drop for PacketSniffer {
    fn drop(&mut self) {
        self.wpcap.close(self.handle);
    }
}

impl PacketSniffer {
    pub fn new(interface: Option<&str>, target_ip: Option<Ipv4Addr>) -> std::io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let _ = target_ip;
            let sock = Socket::new(
                Domain::PACKET,
                Type::RAW,
                Some(Protocol::from((libc::ETH_P_ALL as u16).to_be() as i32)),
            )?;

            // Set socket timeout for non-blocking loop checks
            sock.set_read_timeout(Some(std::time::Duration::from_millis(50)))?;

            if let Some(iface) = interface {
                let iface_idx = unsafe {
                    let ifname = std::ffi::CString::new(iface).unwrap();
                    libc::if_nametoindex(ifname.as_ptr())
                };

                if iface_idx != 0 {
                    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
                    sll.sll_family = libc::AF_PACKET as u16;
                    sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
                    sll.sll_ifindex = iface_idx as i32;

                    let sockaddr = unsafe {
                        socket2::SockAddr::new(
                            *(&sll as *const libc::sockaddr_ll as *const libc::sockaddr_storage),
                            std::mem::size_of::<libc::sockaddr_ll>() as u32,
                        )
                    };
                    sock.bind(&sockaddr)?;
                }
            }

            Ok(Self {
                socket: sock,
                buffer: vec![0u8; 65536],
            })
        }

        #[cfg(all(not(target_os = "linux"), not(windows)))]
        {
            let _ = (interface, target_ip);
            let sock = Socket::new(Domain::IPV4, Type::RAW, None)?;
            let _ = sock.set_read_timeout(Some(std::time::Duration::from_millis(50)));
            Ok(Self {
                socket: sock,
                buffer: vec![0u8; 65536],
            })
        }

        #[cfg(windows)]
        {
            let wpcap = Wpcap::load().map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::NotConnected, e)
            })?;

            let dev_name = if let Some(iface) = interface {
                let adapters = get_windows_adapters();
                if let Some(a) = adapters.iter().find(|a| {
                    a.friendly_name.eq_ignore_ascii_case(iface)
                        || a.adapter_name.eq_ignore_ascii_case(iface)
                }) {
                    format!(r"\Device\NPF_{}", a.adapter_name)
                } else if iface.starts_with(r"\Device\NPF_") {
                    iface.to_string()
                } else {
                    format!(r"\Device\NPF_{}", iface)
                }
            } else if let Some(dst) = target_ip {
                let route = get_best_route_info(dst).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::NotFound, e)
                })?;
                route.npcap_device_name
            } else {
                // Find first adapter with an IP address
                let adapters = get_windows_adapters();
                let def = adapters
                    .iter()
                    .find(|a| !a.ipv4_addrs.is_empty())
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "No active network adapter found",
                        )
                    })?;
                format!(r"\Device\NPF_{}", def.adapter_name)
            };

            let handle = wpcap.open_live(&dev_name, 65536, true, 50).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::Other, e)
            })?;

            let datalink_type = wpcap.datalink(handle);

            Ok(Self {
                wpcap,
                handle,
                datalink_type,
                current_packet: Vec::new(),
            })
        }
    }

    /// Receives a packet and returns a reference to the IPv4 portion of the buffer.
    pub fn recv_ipv4_packet(&mut self) -> std::io::Result<Option<&[u8]>> {
        #[cfg(not(windows))]
        {
            let uninit_buf = unsafe {
                &mut *(self.buffer.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>])
            };
            match self.socket.recv(uninit_buf) {
                Ok(n) => {
                    #[cfg(target_os = "linux")]
                    {
                        // Check if ethernet frame (14 bytes)
                        if n < 14 {
                            return Ok(None);
                        }
                        let ether_type = u16::from_be_bytes([self.buffer[12], self.buffer[13]]);
                        if ether_type == 0x0800 {
                            // IPv4 packet starts at offset 14
                            return Ok(Some(&self.buffer[14..n]));
                        }
                        Ok(None)
                    }

                    #[cfg(not(target_os = "linux"))]
                    {
                        if n >= 20 {
                            Ok(Some(&self.buffer[..n]))
                        } else {
                            Ok(None)
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                    Ok(None)
                }
                Err(e) => Err(e),
            }
        }

        #[cfg(windows)]
        {
            match self.wpcap.next_ex(self.handle) {
                Ok(Some(raw_bytes)) => {
                    self.current_packet = raw_bytes;
                    let n = self.current_packet.len();

                    if self.datalink_type == DLT_NULL {
                        // BSD loopback: 4 bytes family header
                        if n >= 24 {
                            Ok(Some(&self.current_packet[4..n]))
                        } else {
                            Ok(None)
                        }
                    } else {
                        // Standard Ethernet frame (DLT_EN10MB): 14 bytes header
                        if n < 34 {
                            return Ok(None);
                        }
                        let ether_type = u16::from_be_bytes([self.current_packet[12], self.current_packet[13]]);
                        if ether_type == 0x0800 {
                            Ok(Some(&self.current_packet[14..n]))
                        } else {
                            Ok(None)
                        }
                    }
                }
                Ok(None) => Ok(None),
                Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
            }
        }
    }
}
