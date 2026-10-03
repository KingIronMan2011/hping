//! Output formatting, hex dumping, and packet logging.
use std::net::Ipv4Addr;

pub fn print_beep() {
    print!("\x07");
}

pub fn hex_dump(packet: &[u8]) {
    for (i, chunk) in packet.chunks(16).enumerate() {
        print!("\t{:04x}  ", i * 16);
        for byte in chunk {
            print!("{:02x} ", byte);
        }
        if chunk.len() < 16 {
            for _ in 0..(16 - chunk.len()) {
                print!("   ");
            }
        }
        print!(" ");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                print!("{}", *byte as char);
            } else {
                print!(".");
            }
        }
        println!();
    }
    println!();
}

pub fn ascii_dump(packet: &[u8]) {
    print!("\t\t");
    for (i, byte) in packet.iter().enumerate() {
        if byte.is_ascii_graphic() || *byte == b' ' {
            print!("{}", *byte as char);
        } else {
            print!(".");
        }
        if (i + 1) % 32 == 0 {
            print!("\n\t\t");
        }
    }
    println!("\n");
}

pub fn format_ip_prefix(
    ip_len: usize,
    src: Ipv4Addr,
    ttl: u8,
    is_df: bool,
    id: u16,
    is_dup: bool,
) -> String {
    format!(
        "{prefix}len={len} ip={src} ttl={ttl} {df}id={id}",
        prefix = if is_dup { "DUP! " } else { "" },
        len = ip_len,
        src = src,
        ttl = ttl,
        df = if is_df { "DF " } else { "" },
        id = id,
    )
}
