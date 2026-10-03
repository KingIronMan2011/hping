//! SCAN mode for high-performance TCP/UDP port scanning.
use std::collections::{BTreeMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rand::Rng;

use crate::args::CliArgs;
use crate::net::iface::get_local_ip_for_dest;
use crate::net::raw_socket::RawSocketSender;
use crate::net::sniffer::PacketSniffer;
use crate::protocol::icmp::*;
use crate::protocol::ipv4::*;
use crate::protocol::tcp::*;
use crate::protocol::udp::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

pub fn parse_ports(spec: &str) -> Vec<u16> {
    let mut ports = HashSet::new();

    for part in spec.split(',') {
        let part = part.trim();
        if let Some((start_str, end_str)) = part.split_once('-') {
            if let (Ok(start), Ok(end)) = (start_str.trim().parse::<u16>(), end_str.trim().parse::<u16>()) {
                for p in start..=end {
                    ports.insert(p);
                }
            }
        } else if let Ok(p) = part.parse::<u16>() {
            ports.insert(p);
        }
    }

    let mut list: Vec<u16> = ports.into_iter().collect();
    list.sort_unstable();
    list
}

pub fn common_service_name(port: u16) -> &'static str {
    match port {
        20 => "ftp-data",
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "domain",
        80 => "http",
        110 => "pop3",
        111 => "sunrpc",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        443 => "https",
        445 => "microsoft-ds",
        993 => "imaps",
        995 => "pop3s",
        1433 => "ms-sql-s",
        1521 => "oracle",
        3306 => "mysql",
        3389 => "ms-wbt-server",
        5432 => "postgresql",
        6379 => "redis",
        8000 => "http-alt",
        8080 => "http-proxy",
        8443 => "https-alt",
        9200 => "elasticsearch",
        _ => "unknown",
    }
}

pub fn run_scan(
    args: &CliArgs,
    dst_ip: Ipv4Addr,
    ports_spec: &str,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ports = parse_ports(ports_spec);
    if ports.is_empty() {
        return Err("No valid ports specified for scan".into());
    }

    let local_ip = if let Some(ref spoof_str) = args.spoof {
        spoof_str.parse::<Ipv4Addr>()?
    } else {
        get_local_ip_for_dest(dst_ip).unwrap_or(Ipv4Addr::new(127, 0, 0, 1))
    };

    println!(
        "Scanning {} ({}) [{} ports]:",
        args.host.as_deref().unwrap_or("target"),
        dst_ip,
        ports.len()
    );
    println!("+---------+---------------+-----------+");
    println!("|  Port   | Service Name  |   State   |");
    println!("+---------+---------------+-----------+");

    let results: Arc<Mutex<BTreeMap<u16, (PortState, String)>>> = Arc::new(Mutex::new(BTreeMap::new()));
    let sniffer_running = Arc::clone(&running);
    let sniffer_results = Arc::clone(&results);
    let sniffer_iface = args.interface.clone();
    let is_udp = args.udp;

    // Sniffer thread for scanning replies
    let sniffer_thread = thread::spawn(move || {
        let mut sniffer = match PacketSniffer::new(sniffer_iface.as_deref()) {
            Ok(s) => s,
            Err(_) => return,
        };

        while sniffer_running.load(Ordering::SeqCst) {
            if let Ok(Some(pkt)) = sniffer.recv_ipv4_packet() {
                if let Ok((ip_hdr, l4)) = Ipv4Header::parse(pkt) {
                    if ip_hdr.src != dst_ip && ip_hdr.protocol != 1 {
                        continue;
                    }

                    if !is_udp && ip_hdr.protocol == 6 {
                        // TCP
                        if let Ok((tcp_hdr, _)) = TcpHeader::parse(l4) {
                            let state = if tcp_hdr.flags & TH_SYN != 0 && tcp_hdr.flags & TH_ACK != 0 {
                                PortState::Open
                            } else if tcp_hdr.flags & TH_RST != 0 {
                                PortState::Closed
                            } else {
                                continue;
                            };

                            let mut res = sniffer_results.lock().unwrap();
                            if !res.contains_key(&tcp_hdr.sport) || state == PortState::Open {
                                res.insert(
                                    tcp_hdr.sport,
                                    (state, tcp_hdr.flags_string()),
                                );
                                if state == PortState::Open {
                                    println!(
                                        "| {:<7} | {:<13} | {:<9} | (flags: {})",
                                        tcp_hdr.sport,
                                        common_service_name(tcp_hdr.sport),
                                        "OPEN",
                                        tcp_hdr.flags_string()
                                    );
                                }
                            }
                        }
                    } else if ip_hdr.protocol == 1 {
                        // ICMP error
                        if let Ok((icmp, _)) = IcmpHeader::parse(l4) {
                            if icmp.icmp_type == ICMP_DEST_UNREACH {
                                // Port unreachable
                            }
                        }
                    }
                }
            }
        }
    });

    let sender = RawSocketSender::new(args.interface.as_deref())?;
    let mut rng = rand::thread_rng();

    // Probe loop
    for &port in &ports {
        if !running.load(Ordering::SeqCst) {
            break;
        }

        let sport: u16 = rng.gen_range(1024..65000);

        let ip_hdr = Ipv4Header {
            version: 4,
            ihl: 5,
            tos: args.parse_tos(),
            total_length: 0,
            id: rng.gen(),
            flags_and_offset: 0,
            ttl: args.ttl,
            protocol: if is_udp { 17 } else { 6 },
            checksum: 0,
            src: local_ip,
            dst: dst_ip,
            options: Vec::new(),
        };

        let l4_bytes = if is_udp {
            let udp = UdpHeader {
                sport,
                dport: port,
                length: 8,
                checksum: 0,
            };
            udp.serialize(local_ip, dst_ip, &[], false)
        } else {
            let tcp = TcpHeader {
                sport,
                dport: port,
                seq: rng.gen(),
                ack: 0,
                data_offset: 5,
                flags: if args.get_tcp_flags() == 0 { TH_SYN } else { args.get_tcp_flags() },
                window_size: args.win,
                checksum: 0,
                urgent_ptr: 0,
                options: Vec::new(),
            };
            tcp.serialize(local_ip, dst_ip, &[], false)
        };

        let mut packet = ip_hdr.serialize(l4_bytes.len());
        packet.extend_from_slice(&l4_bytes);

        let _ = sender.send_packet(&packet, dst_ip);

        // Small pacing between scan probes
        thread::sleep(Duration::from_millis(5));
    }

    // Wait for responses
    let wait_start = Instant::now();
    while wait_start.elapsed() < Duration::from_millis(1500) && running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(50));
    }

    running.store(false, Ordering::SeqCst);
    let _ = sniffer_thread.join();

    println!("+---------+---------------+-----------+");
    println!("Scan finished.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ports() {
        let ports = parse_ports("80,443,1-5,8080-8082");
        assert_eq!(ports, vec![1, 2, 3, 4, 5, 80, 443, 8080, 8081, 8082]);
    }

    #[test]
    fn test_common_services() {
        assert_eq!(common_service_name(80), "http");
        assert_eq!(common_service_name(443), "https");
        assert_eq!(common_service_name(22), "ssh");
        assert_eq!(common_service_name(9999), "unknown");
    }
}
