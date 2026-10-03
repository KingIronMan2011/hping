//! Flood mode implementation for maximum packet throughput.
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use rand::Rng;

use crate::args::CliArgs;
use crate::net::iface::get_local_ip_for_dest;
use crate::net::raw_socket::RawSocketSender;
use crate::protocol::icmp::*;
use crate::protocol::ipv4::*;
use crate::protocol::tcp::*;
use crate::protocol::udp::*;

pub fn run_flood(
    args: &CliArgs,
    dst_ip: Ipv4Addr,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error>> {
    let local_ip = if let Some(ref spoof_str) = args.spoof {
        spoof_str.parse::<Ipv4Addr>()?
    } else {
        get_local_ip_for_dest(dst_ip).unwrap_or(Ipv4Addr::new(127, 0, 0, 1))
    };

    let target_display = args.host.as_deref().unwrap_or("target");
    let (dst_port, inc_dport) = args.parse_dest_port();
    let mut current_dport = dst_port;

    println!(
        "HPING {} ({}: flood mode): sending packets at maximum speed...",
        target_display, dst_ip
    );

    let sender = RawSocketSender::new(args.interface.as_deref())?;
    let mut rng = rand::thread_rng();
    let mut sent: u64 = 0;
    let payload = vec![0u8; args.data_size];

    while running.load(Ordering::Relaxed) {
        if let Some(count) = args.count {
            if sent >= count as u64 {
                break;
            }
        }

        let current_dst = if args.rand_dest {
            Ipv4Addr::new(rng.gen(), rng.gen(), rng.gen(), rng.gen())
        } else {
            dst_ip
        };

        let current_src = if args.rand_source {
            Ipv4Addr::new(rng.gen(), rng.gen(), rng.gen(), rng.gen())
        } else {
            local_ip
        };

        let ip_hdr = Ipv4Header {
            version: 4,
            ihl: 5,
            tos: args.parse_tos(),
            total_length: 0,
            id: rng.gen(),
            flags_and_offset: if args.dontfrag { IP_DF } else { 0 },
            ttl: args.ttl,
            protocol: if args.rawip {
                args.ipproto
            } else if args.icmp {
                1
            } else if args.udp {
                17
            } else {
                6
            },
            checksum: 0,
            src: current_src,
            dst: current_dst,
            options: Vec::new(),
        };

        let l4_bytes = if args.rawip {
            payload.clone()
        } else if args.icmp {
            let icmp = IcmpHeader::echo_request(rng.gen(), sent as u16);
            icmp.serialize(&payload, args.badcksum)
        } else if args.udp {
            let udp = UdpHeader {
                sport: rng.gen_range(1024..65000),
                dport: current_dport,
                length: (8 + payload.len()) as u16,
                checksum: 0,
            };
            udp.serialize(current_src, current_dst, &payload, args.badcksum)
        } else {
            let tcp = TcpHeader {
                sport: rng.gen_range(1024..65000),
                dport: current_dport,
                seq: rng.gen(),
                ack: 0,
                data_offset: 5,
                flags: if args.get_tcp_flags() == 0 { TH_SYN } else { args.get_tcp_flags() },
                window_size: args.win,
                checksum: 0,
                urgent_ptr: 0,
                options: Vec::new(),
            };
            tcp.serialize(current_src, current_dst, &payload, args.badcksum)
        };

        let mut packet = ip_hdr.serialize(l4_bytes.len());
        packet.extend_from_slice(&l4_bytes);

        let _ = sender.send_packet(&packet, current_dst);
        sent += 1;

        if inc_dport {
            current_dport = current_dport.wrapping_add(1);
        }
    }

    println!("\nFlood stopped: {} packets transmitted.", sent);
    Ok(())
}
