//! Packet sniffer using native Linux AF_PACKET raw sockets.
use std::mem::MaybeUninit;
#[cfg(target_os = "linux")]
use socket2::Protocol;
use socket2::{Domain, Socket, Type};

pub struct PacketSniffer {
    socket: Socket,
    buffer: Vec<u8>,
}

impl PacketSniffer {
    pub fn new(interface: Option<&str>) -> std::io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
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

        #[cfg(not(target_os = "linux"))]
        {
            let _ = interface;
            let sock = Socket::new(Domain::IPV4, Type::RAW, None)?;
            let _ = sock.set_read_timeout(Some(std::time::Duration::from_millis(50)));
            Ok(Self {
                socket: sock,
                buffer: vec![0u8; 65536],
            })
        }
    }

    /// Receives a packet and returns a reference to the IPv4 portion of the buffer.
    pub fn recv_ipv4_packet(&mut self) -> std::io::Result<Option<&[u8]>> {
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
}
