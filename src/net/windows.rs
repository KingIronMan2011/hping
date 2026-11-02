//! Dynamic loader and wrapper for Npcap / WinPcap (wpcap.dll) on Windows.
#![cfg(windows)]

use libloading::{Library, Symbol};
use std::ffi::{c_char, c_int, c_uchar, c_uint, c_void, CStr, CString};
use std::net::Ipv4Addr;
use std::ptr;
use std::sync::Arc;
use windows_sys::Win32::Foundation::NO_ERROR;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GetBestRoute2, SendARP, GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH,
    MIB_IPFORWARD_ROW2,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN, SOCKADDR_INET};

pub const DLT_NULL: c_int = 0;
pub const DLT_EN10MB: c_int = 1;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PcapTimeval {
    pub tv_sec: i32,
    pub tv_usec: i32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PcapPkthdr {
    pub ts: PcapTimeval,
    pub caplen: u32,
    pub len: u32,
}

#[repr(C)]
pub struct PcapIf {
    pub next: *mut PcapIf,
    pub name: *mut c_char,
    pub description: *mut c_char,
    pub addresses: *mut PcapAddr,
    pub flags: c_uint,
}

#[repr(C)]
pub struct PcapAddr {
    pub next: *mut PcapAddr,
    pub addr: *mut c_void,
    pub netmask: *mut c_void,
    pub broadaddr: *mut c_void,
    pub dstaddr: *mut c_void,
}

pub type PcapT = c_void;

type PcapOpenLiveFn = unsafe extern "C" fn(
    device: *const c_char,
    snaplen: c_int,
    promisc: c_int,
    to_ms: c_int,
    errbuf: *mut c_char,
) -> *mut PcapT;

type PcapCloseFn = unsafe extern "C" fn(p: *mut PcapT);

type PcapSendpacketFn = unsafe extern "C" fn(p: *mut PcapT, buf: *const c_uchar, size: c_int) -> c_int;

type PcapNextExFn = unsafe extern "C" fn(
    p: *mut PcapT,
    pkt_header: *mut *mut PcapPkthdr,
    pkt_data: *mut *const c_uchar,
) -> c_int;

type PcapFindalldevsFn = unsafe extern "C" fn(alldevsp: *mut *mut PcapIf, errbuf: *mut c_char) -> c_int;

type PcapFreealldevsFn = unsafe extern "C" fn(alldevs: *mut PcapIf);

type PcapDatalinkFn = unsafe extern "C" fn(p: *mut PcapT) -> c_int;

pub struct Wpcap {
    _lib: Arc<Library>,
    pcap_open_live: PcapOpenLiveFn,
    pcap_close: PcapCloseFn,
    pcap_sendpacket: PcapSendpacketFn,
    pcap_next_ex: PcapNextExFn,
    pcap_findalldevs: PcapFindalldevsFn,
    pcap_freealldevs: PcapFreealldevsFn,
    pcap_datalink: PcapDatalinkFn,
}

unsafe impl Send for Wpcap {}
unsafe impl Sync for Wpcap {}

impl Wpcap {
    /// Loads wpcap.dll dynamically from system directories or Npcap directory.
    pub fn load() -> Result<Arc<Self>, String> {
        let candidates = [
            r"C:\Windows\System32\Npcap\wpcap.dll",
            r"C:\Windows\System32\wpcap.dll",
            "wpcap.dll",
        ];

        let mut last_err = String::new();
        for &path in &candidates {
            if let Ok(lib) = unsafe { Library::new(path) } {
                let arc_lib = Arc::new(lib);
                unsafe {
                    let open_live: Result<Symbol<PcapOpenLiveFn>, _> = arc_lib.get(b"pcap_open_live\0");
                    let close: Result<Symbol<PcapCloseFn>, _> = arc_lib.get(b"pcap_close\0");
                    let sendpacket: Result<Symbol<PcapSendpacketFn>, _> = arc_lib.get(b"pcap_sendpacket\0");
                    let next_ex: Result<Symbol<PcapNextExFn>, _> = arc_lib.get(b"pcap_next_ex\0");
                    let findalldevs: Result<Symbol<PcapFindalldevsFn>, _> = arc_lib.get(b"pcap_findalldevs\0");
                    let freealldevs: Result<Symbol<PcapFreealldevsFn>, _> = arc_lib.get(b"pcap_freealldevs\0");
                    let datalink: Result<Symbol<PcapDatalinkFn>, _> = arc_lib.get(b"pcap_datalink\0");

                    if let (Ok(o), Ok(c), Ok(s), Ok(n), Ok(fa), Ok(fr), Ok(dl)) = (
                        open_live, close, sendpacket, next_ex, findalldevs, freealldevs, datalink,
                    ) {
                        return Ok(Arc::new(Wpcap {
                            _lib: arc_lib.clone(),
                            pcap_open_live: *o,
                            pcap_close: *c,
                            pcap_sendpacket: *s,
                            pcap_next_ex: *n,
                            pcap_findalldevs: *fa,
                            pcap_freealldevs: *fr,
                            pcap_datalink: *dl,
                        }));
                    }
                }
            } else {
                last_err = format!("Could not load {}", path);
            }
        }

        Err(format!(
            "Npcap or WinPcap is required on Windows to craft and inject raw packets.\n\
             Please install Npcap from https://npcap.com/ (with 'WinPcap API-compatible Mode' checked).\n\
             Detail: {}",
            last_err
        ))
    }

    pub fn open_live(
        &self,
        device: &str,
        snaplen: i32,
        promisc: bool,
        to_ms: i32,
    ) -> Result<*mut PcapT, String> {
        let c_device = CString::new(device).map_err(|e| e.to_string())?;
        let mut errbuf = [0 as c_char; 256];
        let handle = unsafe {
            (self.pcap_open_live)(
                c_device.as_ptr(),
                snaplen,
                if promisc { 1 } else { 0 },
                to_ms,
                errbuf.as_mut_ptr(),
            )
        };

        if handle.is_null() {
            let msg = unsafe { CStr::from_ptr(errbuf.as_ptr()) }.to_string_lossy();
            Err(format!("pcap_open_live failed on {}: {}", device, msg))
        } else {
            Ok(handle)
        }
    }

    pub fn close(&self, handle: *mut PcapT) {
        if !handle.is_null() {
            unsafe {
                (self.pcap_close)(handle);
            }
        }
    }

    pub fn sendpacket(&self, handle: *mut PcapT, buf: &[u8]) -> Result<(), String> {
        let res = unsafe { (self.pcap_sendpacket)(handle, buf.as_ptr(), buf.len() as c_int) };
        if res == 0 {
            Ok(())
        } else {
            Err("pcap_sendpacket failed".to_string())
        }
    }

    pub fn next_ex(&self, handle: *mut PcapT) -> Result<Option<Vec<u8>>, String> {
        let mut hdr: *mut PcapPkthdr = ptr::null_mut();
        let mut data: *const c_uchar = ptr::null();

        let res = unsafe { (self.pcap_next_ex)(handle, &mut hdr, &mut data) };
        match res {
            1 => {
                // Packet read successfully
                if hdr.is_null() || data.is_null() {
                    return Ok(None);
                }
                let caplen = unsafe { (*hdr).caplen } as usize;
                let slice = unsafe { std::slice::from_raw_parts(data, caplen) };
                Ok(Some(slice.to_vec()))
            }
            0 => {
                // Timeout elapsed, no packet
                Ok(None)
            }
            -1 => Err("pcap_next_ex error".to_string()),
            -2 => Ok(None), // EOF
            _ => Ok(None),
        }
    }

    pub fn datalink(&self, handle: *mut PcapT) -> c_int {
        unsafe { (self.pcap_datalink)(handle) }
    }

    /// Finds all available network devices.
    pub fn find_all_devs(&self) -> Result<Vec<(String, Option<String>)>, String> {
        let mut alldevs: *mut PcapIf = ptr::null_mut();
        let mut errbuf = [0 as c_char; 256];

        let res = unsafe { (self.pcap_findalldevs)(&mut alldevs, errbuf.as_mut_ptr()) };
        if res != 0 {
            let msg = unsafe { CStr::from_ptr(errbuf.as_ptr()) }.to_string_lossy();
            return Err(format!("pcap_findalldevs failed: {}", msg));
        }

        let mut list = Vec::new();
        let mut curr = alldevs;
        while !curr.is_null() {
            unsafe {
                let name = if !(*curr).name.is_null() {
                    CStr::from_ptr((*curr).name).to_string_lossy().into_owned()
                } else {
                    String::new()
                };

                let desc = if !(*curr).description.is_null() {
                    Some(CStr::from_ptr((*curr).description).to_string_lossy().into_owned())
                } else {
                    None
                };

                list.push((name, desc));
                curr = (*curr).next;
            }
        }

        unsafe {
            (self.pcap_freealldevs)(alldevs);
        }
        Ok(list)
    }
}

/// Information about a network adapter on Windows.
#[derive(Debug, Clone)]
pub struct WinAdapterInfo {
    pub adapter_name: String,   // e.g. "{GUID}"
    pub friendly_name: String,  // e.g. "Ethernet"
    pub mac_addr: [u8; 6],
    pub ipv4_addrs: Vec<Ipv4Addr>,
    pub if_index: u32,
}

/// Enumerate Windows network adapters with their IP addresses, MAC addresses, and GUIDs.
pub fn get_windows_adapters() -> Vec<WinAdapterInfo> {
    let mut adapters = Vec::new();
    let family = AF_INET as u32;
    let flags = GAA_FLAG_INCLUDE_PREFIX;
    let mut buf_len: u32 = 16384;

    let mut buf = vec![0u8; buf_len as usize];
    let res = unsafe {
        GetAdaptersAddresses(
            family,
            flags,
            ptr::null_mut(),
            buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
            &mut buf_len,
        )
    };

    if res != 0 {
        return adapters;
    }

    let mut curr = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !curr.is_null() {
        unsafe {
            let item = &*curr;
            let adapter_name = if !item.AdapterName.is_null() {
                CStr::from_ptr(item.AdapterName as *const c_char)
                    .to_string_lossy()
                    .into_owned()
            } else {
                String::new()
            };

            let friendly_name = if !item.FriendlyName.is_null() {
                let mut len = 0;
                while *item.FriendlyName.add(len) != 0 {
                    len += 1;
                }
                let slice = std::slice::from_raw_parts(item.FriendlyName, len);
                String::from_utf16_lossy(slice)
            } else {
                String::new()
            };

            let mut mac = [0u8; 6];
            if item.PhysicalAddressLength >= 6 {
                mac.copy_from_slice(&item.PhysicalAddress[..6]);
            }

            let mut ips = Vec::new();
            let mut unicast = item.FirstUnicastAddress;
            while !unicast.is_null() {
                let sock_addr = (*unicast).Address.lpSockaddr;
                if !sock_addr.is_null() && (*sock_addr).sa_family == AF_INET {
                    let sin_addr = (*(sock_addr as *const windows_sys::Win32::Networking::WinSock::SOCKADDR_IN))
                        .sin_addr
                        .S_un
                        .S_addr;
                    ips.push(Ipv4Addr::from(u32::from_ne_bytes(sin_addr.to_ne_bytes())));
                }
                unicast = (*unicast).Next;
            }

            adapters.push(WinAdapterInfo {
                adapter_name,
                friendly_name,
                mac_addr: mac,
                ipv4_addrs: ips,
                if_index: item.Anonymous1.Anonymous.IfIndex,
            });

            curr = item.Next;
        }
    }

    adapters
}

/// Resolves the destination MAC address for an IP address on Windows using SendARP.
pub fn resolve_mac_windows(dst_ip: Ipv4Addr) -> Option<[u8; 6]> {
    let dest_ip_u32 = u32::from_ne_bytes(dst_ip.octets());
    let mut mac_addr = [0u8; 6];
    let mut mac_addr_len: u32 = 6;

    let res = unsafe {
        SendARP(
            dest_ip_u32,
            0,
            mac_addr.as_mut_ptr() as *mut c_void,
            &mut mac_addr_len,
        )
    };

    if res == NO_ERROR && mac_addr_len == 6 {
        Some(mac_addr)
    } else {
        None
    }
}

/// Information needed to route and send packets to a target IP on Windows.
#[derive(Debug, Clone)]
pub struct WinRouteInfo {
    pub if_index: u32,
    pub src_ip: Ipv4Addr,
    pub next_hop: Option<Ipv4Addr>,
    pub local_mac: [u8; 6],
    pub target_mac: [u8; 6],
    pub npcap_device_name: String,
}

/// Finds the routing information (source IP, gateway, local MAC, gateway/target MAC, and Npcap device) for `dst_ip`.
pub fn get_best_route_info(dst_ip: Ipv4Addr) -> Result<WinRouteInfo, String> {
    let adapters = get_windows_adapters();

    // 1. Query BestRoute2
    let mut dest_addr: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    dest_addr.Ipv4 = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: 0,
        sin_addr: windows_sys::Win32::Networking::WinSock::IN_ADDR {
            S_un: windows_sys::Win32::Networking::WinSock::IN_ADDR_0 {
                S_addr: u32::from_ne_bytes(dst_ip.octets()),
            },
        },
        sin_zero: [0; 8],
    };

    let mut best_route: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    let mut best_source_addr: SOCKADDR_INET = unsafe { std::mem::zeroed() };

    let status = unsafe {
        GetBestRoute2(
            ptr::null_mut(),
            0,
            ptr::null(),
            &dest_addr,
            0,
            &mut best_route,
            &mut best_source_addr,
        )
    };

    let (if_index, src_ip, next_hop) = if status == 0 {
        let idx = best_route.InterfaceIndex;
        let s_addr = unsafe { best_source_addr.Ipv4.sin_addr.S_un.S_addr };
        let src = Ipv4Addr::from(u32::from_ne_bytes(s_addr.to_ne_bytes()));

        let gw_addr = unsafe { best_route.NextHop.Ipv4.sin_addr.S_un.S_addr };
        let gw = if gw_addr != 0 {
            Some(Ipv4Addr::from(u32::from_ne_bytes(gw_addr.to_ne_bytes())))
        } else {
            None
        };
        (idx, src, gw)
    } else {
        // Fallback: search adapters for one that has an IP
        let default_adapter = adapters
            .iter()
            .find(|a| !a.ipv4_addrs.is_empty())
            .ok_or_else(|| "No active network adapter found on Windows".to_string())?;
        (
            default_adapter.if_index,
            default_adapter.ipv4_addrs[0],
            None,
        )
    };

    let adapter = adapters
        .iter()
        .find(|a| a.if_index == if_index)
        .or_else(|| adapters.iter().find(|a| a.ipv4_addrs.contains(&src_ip)))
        .ok_or_else(|| format!("Could not find network adapter matching if_index {}", if_index))?;

    // Determine target MAC address:
    // If next_hop exists, ARP the gateway; otherwise ARP destination directly
    let arp_target = next_hop.unwrap_or(dst_ip);
    let target_mac = resolve_mac_windows(arp_target).unwrap_or([0xff; 6]);

    // Format device name for Npcap: \Device\NPF_{GUID}
    let npcap_device_name = format!(r"\Device\NPF_{}", adapter.adapter_name);

    Ok(WinRouteInfo {
        if_index,
        src_ip,
        next_hop,
        local_mac: adapter.mac_addr,
        target_mac,
        npcap_device_name,
    })
}
