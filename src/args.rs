//! CLI argument definitions and parsing via clap.
use clap::Parser;
use std::time::Duration;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "hping",
    author = "Salvatore Sanfilippo <antirez@invece.org>, Rust port contributors",
    version = "3.1.0",
    about = "A command-line oriented TCP/IP packet assembler and analyzer in Rust",
    disable_version_flag = true,
    long_about = None
)]
pub struct CliArgs {
    /// Show version
    #[arg(short = 'v', long = "version", action = clap::ArgAction::Version)]
    pub version: Option<bool>,

    /// Target destination host or IP address
    #[arg(value_name = "HOST")]
    pub host: Option<String>,

    // --- Mode flags ---
    /// RAW IP mode
    #[arg(short = '0', long = "rawip")]
    pub rawip: bool,

    /// ICMP mode
    #[arg(short = '1', long = "icmp")]
    pub icmp: bool,

    /// UDP mode
    #[arg(short = '2', long = "udp")]
    pub udp: bool,

    /// SCAN mode, e.g. --scan 1-1024,8080 or -8 80,443
    #[arg(short = '8', long = "scan", value_name = "PORTS")]
    pub scan: Option<String>,

    /// Listen mode with optional signature
    #[arg(short = '9', long = "listen", value_name = "SIGNATURE")]
    pub listen: Option<Option<String>>,

    // --- Rate & Timing ---
    /// Stop after sending (and receiving) count packets
    #[arg(short = 'c', long = "count", value_name = "COUNT")]
    pub count: Option<usize>,

    /// Packet interval (e.g. 1 for 1 sec, u1000 for 1000 usec)
    #[arg(short = 'i', long = "interval", value_name = "INTERVAL")]
    pub interval: Option<String>,

    /// Fast mode: alias for -i u10000 (10 packets per second)
    #[arg(long = "fast")]
    pub fast: bool,

    /// Faster mode: alias for -i u1000 (100 packets per second)
    #[arg(long = "faster")]
    pub faster: bool,

    /// Flood mode: send packets as fast as possible, don't show replies
    #[arg(long = "flood")]
    pub flood: bool,

    // --- IP Options ---
    /// Spoof source IP address
    #[arg(short = 'a', long = "spoof", value_name = "IP")]
    pub spoof: Option<String>,

    /// Random destination address mode
    #[arg(long = "rand-dest")]
    pub rand_dest: bool,

    /// Random source address mode
    #[arg(long = "rand-source")]
    pub rand_source: bool,

    /// Set TTL (time to live, default 64)
    #[arg(short = 't', long = "ttl", default_value_t = 64)]
    pub ttl: u8,

    /// Set IP ID (default random)
    #[arg(short = 'N', long = "id", value_name = "ID")]
    pub id: Option<u16>,

    /// Relativize IP ID field
    #[arg(short = 'r', long = "rel")]
    pub rel: bool,

    /// Split packet in more fragments
    #[arg(short = 'f', long = "frag")]
    pub frag: bool,

    /// Set More Fragments flag
    #[arg(short = 'x', long = "morefrag")]
    pub morefrag: bool,

    /// Set Don't Fragment flag
    #[arg(short = 'y', long = "dontfrag")]
    pub dontfrag: bool,

    /// Set the fragment offset in bytes
    #[arg(short = 'g', long = "fragoff", default_value_t = 0)]
    pub fragoff: u16,

    /// Set virtual MTU
    #[arg(short = 'm', long = "mtu", default_value_t = 1500)]
    pub mtu: usize,

    /// Type of service (e.g. 0x10)
    #[arg(short = 'o', long = "tos", default_value = "0")]
    pub tos: String,

    /// Include RECORD_ROUTE option
    #[arg(short = 'G', long = "rroute")]
    pub rroute: bool,

    /// Loose source routing IP list
    #[arg(long = "lsrr", value_name = "ROUTELIST")]
    pub lsrr: Option<String>,

    /// Strict source routing IP list
    #[arg(long = "ssrr", value_name = "ROUTELIST")]
    pub ssrr: Option<String>,

    /// Set the IP protocol field (only in RAW IP mode)
    #[arg(short = 'H', long = "ipproto", default_value_t = 6)]
    pub ipproto: u8,

    // --- UDP / TCP Options ---
    /// Base source port (default random)
    #[arg(short = 's', long = "baseport")]
    pub baseport: Option<u16>,

    /// Destination port (e.g. 80, or +80 to increment)
    #[arg(short = 'p', long = "destport", default_value = "0")]
    pub destport: String,

    /// Keep still source port
    #[arg(short = 'k', long = "keep")]
    pub keep: bool,

    /// TCP window size (default 64)
    #[arg(short = 'w', long = "win", default_value_t = 64)]
    pub win: u16,

    /// Set fake TCP data offset
    #[arg(short = 'O', long = "tcpoff")]
    pub tcpoff: Option<u8>,

    /// Show only TCP sequence number
    #[arg(short = 'Q', long = "seqnum")]
    pub seqnum: bool,

    /// Send packets with bad checksum
    #[arg(short = 'b', long = "badcksum")]
    pub badcksum: bool,

    /// Set TCP sequence number
    #[arg(short = 'M', long = "setseq")]
    pub setseq: Option<u32>,

    /// Set TCP ACK number
    #[arg(short = 'L', long = "setack")]
    pub setack: Option<u32>,

    // --- TCP Flags ---
    /// Set FIN flag
    #[arg(short = 'F', long = "fin")]
    pub fin: bool,

    /// Set SYN flag
    #[arg(short = 'S', long = "syn")]
    pub syn: bool,

    /// Set RST flag
    #[arg(short = 'R', long = "rst")]
    pub rst: bool,

    /// Set PUSH flag
    #[arg(short = 'P', long = "push")]
    pub push: bool,

    /// Set ACK flag
    #[arg(short = 'A', long = "ack")]
    pub ack: bool,

    /// Set URG flag
    #[arg(short = 'U', long = "urg")]
    pub urg: bool,

    /// Set Xmas unused flag (0x40)
    #[arg(short = 'X', long = "xmas")]
    pub xmas: bool,

    /// Set Ymas unused flag (0x80)
    #[arg(short = 'Y', long = "ymas")]
    pub ymas: bool,

    /// Use last TCP flags as exit code
    #[arg(long = "tcpexitcode")]
    pub tcpexitcode: bool,

    /// Enable TCP timestamp option
    #[arg(long = "tcp-timestamp")]
    pub tcp_timestamp: bool,

    // --- ICMP Options ---
    /// ICMP type (default 8: echo request)
    #[arg(short = 'C', long = "icmptype", default_value_t = 8)]
    pub icmptype: u8,

    /// ICMP code (default 0)
    #[arg(short = 'K', long = "icmpcode", default_value_t = 0)]
    pub icmpcode: u8,

    /// Alias for --icmp --icmptype 13 (ICMP timestamp)
    #[arg(long = "icmp-ts")]
    pub icmp_ts: bool,

    /// Alias for --icmp --icmptype 17 (ICMP address subnet mask)
    #[arg(long = "icmp-addr")]
    pub icmp_addr: bool,

    /// Gateway address for ICMP redirect
    #[arg(long = "icmp-gw")]
    pub icmp_gw: Option<String>,

    // --- Payload & Data ---
    /// Payload data size (default 0)
    #[arg(short = 'd', long = "data", default_value_t = 0)]
    pub data_size: usize,

    /// Read payload data from file
    #[arg(short = 'E', long = "file", value_name = "FILE")]
    pub file: Option<String>,

    /// Add signature
    #[arg(short = 'e', long = "sign", value_name = "SIGNATURE")]
    pub sign: Option<String>,

    /// Dump packets in hex
    #[arg(short = 'j', long = "dump")]
    pub dump: bool,

    /// Dump printable characters
    #[arg(short = 'J', long = "print")]
    pub print: bool,

    /// Enable safe protocol
    #[arg(short = 'B', long = "safe")]
    pub safe: bool,

    // --- Traceroute ---
    /// Traceroute mode (implies --ttl 1)
    #[arg(short = 'T', long = "traceroute")]
    pub traceroute: bool,

    /// Stop traceroute on first non-ICMP response
    #[arg(long = "tr-stop")]
    pub tr_stop: bool,

    /// Keep source TTL fixed in traceroute mode
    #[arg(long = "tr-keep-ttl")]
    pub tr_keep_ttl: bool,

    /// Don't calculate/show RTT in traceroute mode
    #[arg(long = "tr-no-rtt")]
    pub tr_no_rtt: bool,

    // --- General / UI ---
    /// Network interface name
    #[arg(short = 'I', long = "interface", value_name = "IFACE")]
    pub interface: Option<String>,

    /// Numeric output (no reverse DNS)
    #[arg(short = 'n', long = "numeric")]
    pub numeric: bool,

    /// Quiet mode (do not display replies)
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,

    /// Verbose output
    #[arg(short = 'V', long = "verbose")]
    pub verbose: bool,

    /// Debug output
    #[arg(short = 'D', long = "debug")]
    pub debug: bool,

    /// Beep for every matching packet received
    #[arg(long = "beep")]
    pub beep: bool,
}

impl CliArgs {
    pub fn get_interval(&self) -> Duration {
        if self.flood {
            return Duration::ZERO;
        }
        if self.faster {
            return Duration::from_micros(1000);
        }
        if self.fast {
            return Duration::from_micros(10000);
        }
        if let Some(ref s) = self.interval {
            if s.starts_with('u') {
                if let Ok(usecs) = s[1..].parse::<u64>() {
                    return Duration::from_micros(usecs);
                }
            } else if let Ok(secs) = s.parse::<f64>() {
                return Duration::from_secs_f64(secs);
            }
        }
        Duration::from_secs(1)
    }

    pub fn get_tcp_flags(&self) -> u8 {
        let mut flags = 0u8;
        if self.fin { flags |= crate::protocol::tcp::TH_FIN; }
        if self.syn { flags |= crate::protocol::tcp::TH_SYN; }
        if self.rst { flags |= crate::protocol::tcp::TH_RST; }
        if self.push { flags |= crate::protocol::tcp::TH_PUSH; }
        if self.ack { flags |= crate::protocol::tcp::TH_ACK; }
        if self.urg { flags |= crate::protocol::tcp::TH_URG; }
        if self.xmas { flags |= crate::protocol::tcp::TH_X; }
        if self.ymas { flags |= crate::protocol::tcp::TH_Y; }
        flags
    }

    pub fn parse_dest_port(&self) -> (u16, bool) {
        let mut s = self.destport.as_str();
        let mut inc = false;
        if s.starts_with('+') {
            inc = true;
            s = &s[1..];
            if s.starts_with('+') {
                s = &s[1..];
            }
        }
        (s.parse::<u16>().unwrap_or(0), inc)
    }

    pub fn parse_tos(&self) -> u8 {
        if self.tos.starts_with("0x") || self.tos.starts_with("0X") {
            u8::from_str_radix(&self.tos[2..], 16).unwrap_or(0)
        } else {
            self.tos.parse::<u8>().unwrap_or(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dest_port() {
        let mut args = CliArgs::parse_from(["hping", "127.0.0.1", "-p", "80"]);
        assert_eq!(args.parse_dest_port(), (80, false));

        args = CliArgs::parse_from(["hping", "127.0.0.1", "-p", "+80"]);
        assert_eq!(args.parse_dest_port(), (80, true));

        args = CliArgs::parse_from(["hping", "127.0.0.1", "-p", "++80"]);
        assert_eq!(args.parse_dest_port(), (80, true));
    }

    #[test]
    fn test_intervals() {
        let mut args = CliArgs::parse_from(["hping", "127.0.0.1"]);
        assert_eq!(args.get_interval(), Duration::from_secs(1));

        args = CliArgs::parse_from(["hping", "127.0.0.1", "--fast"]);
        assert_eq!(args.get_interval(), Duration::from_micros(10000));

        args = CliArgs::parse_from(["hping", "127.0.0.1", "--faster"]);
        assert_eq!(args.get_interval(), Duration::from_micros(1000));

        args = CliArgs::parse_from(["hping", "127.0.0.1", "--flood"]);
        assert_eq!(args.get_interval(), Duration::ZERO);

        args = CliArgs::parse_from(["hping", "127.0.0.1", "-i", "u500"]);
        assert_eq!(args.get_interval(), Duration::from_micros(500));
    }

    #[test]
    fn test_tcp_flags() {
        let args = CliArgs::parse_from(["hping", "127.0.0.1", "-S", "-A"]);
        assert_eq!(
            args.get_tcp_flags(),
            crate::protocol::tcp::TH_SYN | crate::protocol::tcp::TH_ACK
        );
    }

    #[test]
    fn test_tos_parsing() {
        let mut args = CliArgs::parse_from(["hping", "127.0.0.1", "-o", "0x10"]);
        assert_eq!(args.parse_tos(), 0x10);

        args = CliArgs::parse_from(["hping", "127.0.0.1", "-o", "16"]);
        assert_eq!(args.parse_tos(), 16);
    }
}
