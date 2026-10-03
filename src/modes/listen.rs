//! Listen mode implementation for passive packet monitoring and signature matching.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::args::CliArgs;
use crate::core::display::*;
use crate::net::sniffer::PacketSniffer;
use crate::protocol::ipv4::*;

pub fn run_listen(
    args: &CliArgs,
    signature: Option<&str>,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "HPING listen mode: interface={}, signature={}",
        args.interface.as_deref().unwrap_or("default"),
        signature.unwrap_or("none")
    );

    let mut sniffer = PacketSniffer::new(args.interface.as_deref())?;

    while running.load(Ordering::SeqCst) {
        if let Ok(Some(pkt)) = sniffer.recv_ipv4_packet() {
            let matched = if let Some(sig) = signature {
                let sig_bytes = sig.as_bytes();
                pkt.windows(sig_bytes.len()).any(|w| w == sig_bytes)
            } else {
                true
            };

            if matched {
                if let Ok((ip_hdr, _)) = Ipv4Header::parse(pkt) {
                    if args.beep { print_beep(); }
                    println!(
                        "Captured: len={} ip={} -> {} proto={} ttl={}",
                        pkt.len(),
                        ip_hdr.src,
                        ip_hdr.dst,
                        ip_hdr.protocol,
                        ip_hdr.ttl
                    );
                    if args.dump { hex_dump(pkt); }
                    if args.print { ascii_dump(pkt); }
                }
            }
        }
        thread::sleep(Duration::from_millis(5));
    }

    Ok(())
}
