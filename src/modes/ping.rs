//! Ping mode implementation (TCP, UDP, ICMP, and RAW IP).
use std::fs::File;
use std::io::Read;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rand::Rng;

use crate::args::CliArgs;
use crate::core::delaytable::SharedDelayTable;
use crate::core::display::*;
use crate::core::stats::Statistics;
use crate::net::iface::get_local_ip_for_dest;
use crate::net::raw_socket::RawSocketSender;
use crate::net::sniffer::PacketSniffer;
use crate::protocol::icmp::*;
use crate::protocol::ipv4::*;
use crate::protocol::tcp::*;
use crate::protocol::udp::*;

pub fn run_ping(args: &CliArgs, dst_ip: Ipv4Addr, running: Arc<AtomicBool>) -> Result<(), Box<dyn std::error::Error>> {
    let local_ip = if let Some(ref spoof_str) = args.spoof {
        spoof_str.parse::<Ipv4Addr>()?
    } else {
        get_local_ip_for_dest(dst_ip).unwrap_or(Ipv4Addr::new(127, 0, 0, 1))
    };

    let target_display = args.host.as_deref().unwrap_or("target");
    let stats = Arc::new(Statistics::new(target_display.to_string()));
    let delay_table = Arc::new(SharedDelayTable::new());

    let (mut dst_port, inc_dport) = args.parse_dest_port();
    let initsport: u16 = args.baseport.unwrap_or_else(|| {
        let mut rng = rand::thread_rng();
        rng.gen_range(1024..65000)
    });
    let mut current_sport = initsport;

    println!(
        "HPING {} ({}: {}): mode={}, {} data bytes",
        target_display,
        if args.icmp {
            "icmp"
        } else if args.udp {
            "udp"
        } else if args.rawip {
            "rawip"
        } else {
            "tcp"
        },
        dst_ip,
        if args.icmp {
            "ICMP"
        } else if args.udp {
            "UDP"
        } else if args.rawip {
            "RAWIP"
        } else {
            "TCP"
        },
        args.data_size
    );

    // Prepare payload data
    let mut payload = vec![0u8; args.data_size];
    if let Some(ref file_path) = args.file {
        if let Ok(mut f) = File::open(file_path) {
            let mut file_buf = Vec::new();
            let _ = f.read_to_end(&mut file_buf);
            if !file_buf.is_empty() {
                payload = file_buf;
            }
        }
    } else if let Some(ref sig) = args.sign {
        let sig_bytes = sig.as_bytes();
        let len = sig_bytes.len().min(payload.len());
        if len > 0 {
            payload[..len].copy_from_slice(&sig_bytes[..len]);
        }
    }

    // Spawn Receiver / Sniffer thread
    let sniffer_running = Arc::clone(&running);
    let sniffer_stats = Arc::clone(&stats);
    let sniffer_delay_table = Arc::clone(&delay_table);
    let sniffer_iface = args.interface.clone();
    let quiet = args.quiet;
    let verbose = args.verbose;
    let dump_hex = args.dump;
    let dump_ascii = args.print;
    let beep = args.beep;
    let show_seqnum = args.seqnum;
    let max_count = args.count;

    let sniffer_thread = thread::spawn(move || {
        let mut sniffer = match PacketSniffer::new(sniffer_iface.as_deref()) {
            Ok(s) => s,
            Err(_) => return,
        };

        while sniffer_running.load(Ordering::SeqCst) {
            if let Ok(Some(pkt_bytes)) = sniffer.recv_ipv4_packet() {
                if let Ok((ip_hdr, l4_payload)) = Ipv4Header::parse(pkt_bytes) {
                    // Filter packets from target destination unless random destination mode is on
                    if ip_hdr.src != dst_ip && ip_hdr.protocol != 1 {
                        continue;
                    }

                    match ip_hdr.protocol {
                        6 => {
                            // TCP
                            if let Ok((tcp_hdr, _)) = TcpHeader::parse(l4_payload) {
                                if tcp_hdr.sport == dst_port || inc_dport {
                                    if beep { print_beep(); }
                                    let (is_dup, rtt_ms, seq) = sniffer_delay_table.match_packet(None, Some(tcp_hdr.dport));
                                    sniffer_stats.inc_received();

                                    if show_seqnum {
                                        println!("{:10} +{}", tcp_hdr.seq, 0);
                                    } else if !quiet {
                                        let prefix = format_ip_prefix(
                                            pkt_bytes.len(),
                                            ip_hdr.src,
                                            ip_hdr.ttl,
                                            ip_hdr.is_df(),
                                            ip_hdr.id,
                                            is_dup,
                                        );
                                        println!(
                                            "{} sport={} flags={} seq={} win={} rtt={:.1} ms",
                                            prefix,
                                            tcp_hdr.sport,
                                            tcp_hdr.flags_string(),
                                            seq,
                                            tcp_hdr.window_size,
                                            rtt_ms
                                        );
                                        if verbose {
                                            println!(
                                                "  seq={} ack={} sum={:x} urp={}",
                                                tcp_hdr.seq, tcp_hdr.ack, tcp_hdr.checksum, tcp_hdr.urgent_ptr
                                            );
                                        }
                                        if dump_hex { hex_dump(pkt_bytes); }
                                        if dump_ascii { ascii_dump(pkt_bytes); }
                                    }
                                }
                            }
                        }
                        17 => {
                            // UDP
                            if let Ok((udp_hdr, _)) = UdpHeader::parse(l4_payload) {
                                if udp_hdr.sport == dst_port || inc_dport {
                                    if beep { print_beep(); }
                                    let (is_dup, rtt_ms, seq) = sniffer_delay_table.match_packet(None, Some(udp_hdr.dport));
                                    sniffer_stats.inc_received();

                                    if !quiet {
                                        let prefix = format_ip_prefix(
                                            pkt_bytes.len(),
                                            ip_hdr.src,
                                            ip_hdr.ttl,
                                            ip_hdr.is_df(),
                                            ip_hdr.id,
                                            is_dup,
                                        );
                                        println!("{} seq={} rtt={:.1} ms", prefix, seq, rtt_ms);
                                        if dump_hex { hex_dump(pkt_bytes); }
                                        if dump_ascii { ascii_dump(pkt_bytes); }
                                    }
                                }
                            }
                        }
                        1 => {
                            // ICMP
                            if let Ok((icmp_hdr, _icmp_payload)) = IcmpHeader::parse(l4_payload) {
                                if icmp_hdr.icmp_type == ICMP_ECHOREPLY {
                                    let seq = icmp_hdr.seq() as u32;
                                    let (is_dup, rtt_ms, _) = sniffer_delay_table.match_packet(Some(seq), None);
                                    sniffer_stats.inc_received();

                                    if beep { print_beep(); }
                                    if !quiet {
                                        let prefix = format_ip_prefix(
                                            pkt_bytes.len(),
                                            ip_hdr.src,
                                            ip_hdr.ttl,
                                            ip_hdr.is_df(),
                                            ip_hdr.id,
                                            is_dup,
                                        );
                                        println!("{} icmp_seq={} rtt={:.1} ms", prefix, seq, rtt_ms);
                                        if dump_hex { hex_dump(pkt_bytes); }
                                        if dump_ascii { ascii_dump(pkt_bytes); }
                                    }
                                } else if icmp_hdr.icmp_type == ICMP_DEST_UNREACH {
                                    // Destination Unreachable
                                    sniffer_stats.inc_received();
                                    if !quiet {
                                        println!(
                                            "ICMP {} from ip={}",
                                            icmp_unreach_description(icmp_hdr.code),
                                            ip_hdr.src
                                        );
                                    }
                                } else if icmp_hdr.icmp_type == ICMP_TIME_EXCEEDED {
                                    // Time Exceeded
                                    sniffer_stats.inc_received();
                                    if !quiet {
                                        println!(
                                            "ICMP {} from ip={}",
                                            icmp_time_exceeded_description(icmp_hdr.code),
                                            ip_hdr.src
                                        );
                                    }
                                }
                            }
                        }
                        _ => {}
                    }

                    if let Some(cnt) = max_count {
                        if sniffer_stats.received.load(Ordering::SeqCst) >= cnt {
                            sniffer_running.store(false, Ordering::SeqCst);
                            break;
                        }
                    }
                }
            }
        }
    });

    let sender = RawSocketSender::new(args.interface.as_deref())?;
    let interval = args.get_interval();
    let mut sequence: u32 = 0;
    let mut rng = rand::thread_rng();

    while running.load(Ordering::SeqCst) {
        if let Some(count) = args.count {
            if sequence as usize >= count {
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

        let packet_id = args.id.unwrap_or_else(|| rng.gen());

        let ip_hdr = Ipv4Header {
            version: 4,
            ihl: 5,
            tos: args.parse_tos(),
            total_length: 0,
            id: packet_id,
            flags_and_offset: if args.dontfrag {
                IP_DF
            } else if args.morefrag {
                IP_MF
            } else {
                0
            } | ((args.fragoff / 8) & IP_OFFSET_MASK),
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
            let icmp_type = if args.icmp_ts {
                ICMP_TIMESTAMP
            } else if args.icmp_addr {
                ICMP_ADDRESS
            } else {
                args.icmptype
            };

            let icmp_hdr = if icmp_type == ICMP_TIMESTAMP {
                IcmpHeader::timestamp_request(rng.gen(), sequence as u16)
            } else if icmp_type == ICMP_ADDRESS {
                IcmpHeader::address_mask_request(rng.gen(), sequence as u16)
            } else {
                IcmpHeader::echo_request(rng.gen(), sequence as u16)
            };
            icmp_hdr.serialize(&payload, args.badcksum)
        } else if args.udp {
            let udp_hdr = UdpHeader {
                sport: current_sport,
                dport: dst_port,
                length: (8 + payload.len()) as u16,
                checksum: 0,
            };
            udp_hdr.serialize(current_src, current_dst, &payload, args.badcksum)
        } else {
            // TCP
            let mut tcp_hdr = TcpHeader {
                sport: current_sport,
                dport: dst_port,
                seq: args.setseq.unwrap_or_else(|| rng.gen()),
                ack: args.setack.unwrap_or(0),
                data_offset: args.tcpoff.unwrap_or(5),
                flags: args.get_tcp_flags(),
                window_size: args.win,
                checksum: 0,
                urgent_ptr: 0,
                options: Vec::new(),
            };

            if args.tcp_timestamp {
                let tsval: u32 = rng.gen();
                tcp_hdr.options.extend_from_slice(&[1, 1, 8, 10]);
                tcp_hdr.options.extend_from_slice(&tsval.to_be_bytes());
                tcp_hdr.options.extend_from_slice(&0u32.to_be_bytes());
                tcp_hdr.data_offset = (20 + tcp_hdr.options.len() as u8 + 3) / 4;
            }

            tcp_hdr.serialize(current_src, current_dst, &payload, args.badcksum)
        };

        // Record in delay table
        delay_table.add(sequence, current_sport);

        // Send packet(s), applying fragmentation if necessary
        let fragments = if args.frag || (ip_hdr.serialize(0).len() + l4_bytes.len() > args.mtu) {
            fragment_packet(ip_hdr, &l4_bytes, args.mtu)
        } else {
            let mut full = ip_hdr.serialize(l4_bytes.len());
            full.extend_from_slice(&l4_bytes);
            vec![full]
        };

        for frag in fragments {
            let _ = sender.send_packet(&frag, current_dst);
        }

        stats.inc_sent();
        sequence = sequence.wrapping_add(1);

        if !args.keep {
            current_sport = current_sport.wrapping_add(1);
            if current_sport < 1024 {
                current_sport = 1024;
            }
        }

        if inc_dport {
            dst_port = dst_port.wrapping_add(1);
        }

        if interval > Duration::ZERO {
            thread::sleep(interval);
        }
    }

    // Wait a brief moment for trailing replies
    if !args.flood && stats.received.load(Ordering::SeqCst) < sequence as usize {
        let wait_start = Instant::now();
        while wait_start.elapsed().as_millis() < 1000 && running.load(Ordering::SeqCst) {
            thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    running.store(false, Ordering::SeqCst);
    let _ = sniffer_thread.join();

    let (rtt_min, rtt_avg, rtt_max) = delay_table.stats();
    stats.print_summary(rtt_min, rtt_avg, rtt_max);

    Ok(())
}
