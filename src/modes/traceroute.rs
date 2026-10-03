//! Traceroute mode implementation.
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use dns_lookup::lookup_addr;
use rand::Rng;

use crate::args::CliArgs;
use crate::core::delaytable::SharedDelayTable;
use crate::net::iface::get_local_ip_for_dest;
use crate::net::raw_socket::RawSocketSender;
use crate::net::sniffer::PacketSniffer;
use crate::protocol::icmp::*;
use crate::protocol::ipv4::*;
use crate::protocol::tcp::*;
use crate::protocol::udp::*;

pub fn run_traceroute(args: &CliArgs, dst_ip: Ipv4Addr, running: Arc<AtomicBool>) -> Result<(), Box<dyn std::error::Error>> {
    let local_ip = if let Some(ref spoof_str) = args.spoof {
        spoof_str.parse::<Ipv4Addr>()?
    } else {
        get_local_ip_for_dest(dst_ip).unwrap_or(Ipv4Addr::new(127, 0, 0, 1))
    };

    let target_display = args.host.as_deref().unwrap_or("target");
    let (dst_port, _) = args.parse_dest_port();
    let delay_table = Arc::new(SharedDelayTable::new());

    println!("HPING {} (traceroute mode): hop discovery over {}", target_display, dst_ip);

    let sender = RawSocketSender::new(args.interface.as_deref())?;
    let mut sniffer = PacketSniffer::new(args.interface.as_deref())?;

    let mut current_ttl = if args.ttl != 64 { args.ttl } else { 1 };
    let max_ttl = 30u8.max(current_ttl);
    let mut rng = rand::thread_rng();
    let mut seq: u32 = 0;

    while running.load(Ordering::SeqCst) && current_ttl <= max_ttl {
        let sport: u16 = rng.gen_range(1024..65000);

        let ip_hdr = Ipv4Header {
            version: 4,
            ihl: 5,
            tos: args.parse_tos(),
            total_length: 0,
            id: rng.gen(),
            flags_and_offset: 0,
            ttl: current_ttl,
            protocol: if args.udp { 17 } else if args.icmp { 1 } else { 6 },
            checksum: 0,
            src: local_ip,
            dst: dst_ip,
            options: Vec::new(),
        };

        let l4_bytes = if args.udp {
            let udp = UdpHeader {
                sport,
                dport: dst_port,
                length: 8,
                checksum: 0,
            };
            udp.serialize(local_ip, dst_ip, &[], false)
        } else if args.icmp {
            let icmp = IcmpHeader::echo_request(rng.gen(), seq as u16);
            icmp.serialize(&[], false)
        } else {
            let tcp = TcpHeader {
                sport,
                dport: dst_port,
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

        delay_table.add(seq, sport);
        sender.send_packet(&packet, dst_ip)?;

        // Wait for hop response
        let wait_start = Instant::now();
        let timeout = Duration::from_millis(1500);
        let mut hop_found = false;

        while wait_start.elapsed() < timeout && running.load(Ordering::SeqCst) {
            if let Ok(Some(recv_pkt)) = sniffer.recv_ipv4_packet() {
                if let Ok((recv_ip, l4)) = Ipv4Header::parse(recv_pkt) {
                    if recv_ip.protocol == 1 {
                        // ICMP
                        if let Ok((icmp, _)) = IcmpHeader::parse(l4) {
                            if icmp.icmp_type == ICMP_TIME_EXCEEDED {
                                let (_, rtt, _) = delay_table.match_packet(Some(seq), Some(sport));
                                let hostname_str = if !args.numeric {
                                    lookup_addr(&recv_ip.src.into())
                                        .map(|name| format!(" name={}", name))
                                        .unwrap_or_default()
                                } else {
                                    String::new()
                                };

                                println!(
                                    "hop={} TTL 0 during transit from ip={}{}{} hoprtt={:.1} ms",
                                    current_ttl,
                                    recv_ip.src,
                                    hostname_str,
                                    if args.tr_no_rtt { "" } else { "" },
                                    rtt
                                );
                                hop_found = true;
                                break;
                            } else if icmp.icmp_type == ICMP_DEST_UNREACH {
                                println!(
                                    "hop={} ICMP {} from ip={}",
                                    current_ttl,
                                    icmp_unreach_description(icmp.code),
                                    recv_ip.src
                                );
                                if args.tr_stop {
                                    return Ok(());
                                }
                                hop_found = true;
                                break;
                            }
                        }
                    } else if recv_ip.src == dst_ip {
                        // Reached target directly
                        println!("hop={} Reached target host ip={}", current_ttl, recv_ip.src);
                        return Ok(());
                    }
                }
            }
            thread::sleep(Duration::from_millis(10));
        }

        if !hop_found {
            println!("hop={} * * * (timeout)", current_ttl);
        }

        seq = seq.wrapping_add(1);
        if !args.tr_keep_ttl {
            current_ttl += 1;
        }

        thread::sleep(Duration::from_millis(100));
    }

    Ok(())
}
