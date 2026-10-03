use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::Parser;
use dns_lookup::getaddrinfo;

use hping::args::CliArgs;
use hping::modes::{run_flood, run_listen, run_ping, run_scan, run_traceroute};

fn resolve_host(host_str: &str) -> Result<Ipv4Addr, String> {
    if let Ok(ip) = Ipv4Addr::from_str(host_str) {
        return Ok(ip);
    }

    match getaddrinfo(Some(host_str), None, None) {
        Ok(addrs) => {
            for addr_result in addrs {
                if let Ok(addr) = addr_result {
                    if let std::net::SocketAddr::V4(v4) = addr.sockaddr {
                        return Ok(*v4.ip());
                    }
                }
            }
            Err(format!("Could not resolve IPv4 address for {}", host_str))
        }
        Err(e) => Err(format!("DNS resolution failed for {}: {:?}", host_str, e)),
    }
}

fn main() {
    let args = CliArgs::parse();

    let running = Arc::new(AtomicBool::new(true));
    let r = Arc::clone(&running);
    if let Err(e) = ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }) {
        eprintln!("Warning: failed to set Ctrl-C handler: {}", e);
    }

    // Check for listen mode
    if let Some(ref sig_opt) = args.listen {
        if let Err(e) = run_listen(&args, sig_opt.as_deref(), running) {
            eprintln!("Listen error: {}", e);
            std::process::exit(1);
        }
        return;
    }

    let host_str = match args.host.as_deref() {
        Some(h) => h,
        None => {
            eprintln!("Error: Target host is required.\nRun 'hping --help' for usage.");
            std::process::exit(1);
        }
    };

    let dst_ip = match resolve_host(host_str) {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!("Resolution error: {}", e);
            std::process::exit(1);
        }
    };

    let result = if let Some(ref ports_spec) = args.scan {
        run_scan(&args, dst_ip, ports_spec, running)
    } else if args.flood {
        run_flood(&args, dst_ip, running)
    } else if args.traceroute {
        run_traceroute(&args, dst_ip, running)
    } else {
        run_ping(&args, dst_ip, running)
    };

    if let Err(e) = result {
        eprintln!("hping error: {}", e);
        std::process::exit(1);
    }
}
