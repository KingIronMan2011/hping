//! Internet Checksum implementation (RFC 1071)
use std::net::Ipv4Addr;

/// Computes the standard Internet Checksum over a byte slice.
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);

    for chunk in &mut chunks {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]);
        sum += word as u32;
    }

    let remainder = chunks.remainder();
    if !remainder.is_empty() {
        sum += (remainder[0] as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !(sum as u16)
}

/// Computes the transport layer checksum with an IPv4 pseudo-header.
pub fn pseudo_header_checksum(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    l4_payload: &[u8],
) -> u16 {
    let mut sum: u32 = 0;

    // Source IP
    for octet_pair in src.octets().chunks_exact(2) {
        sum += u16::from_be_bytes([octet_pair[0], octet_pair[1]]) as u32;
    }

    // Destination IP
    for octet_pair in dst.octets().chunks_exact(2) {
        sum += u16::from_be_bytes([octet_pair[0], octet_pair[1]]) as u32;
    }

    // Protocol
    sum += protocol as u32;

    // L4 Length
    sum += l4_payload.len() as u32;

    // L4 payload (header + data)
    let mut chunks = l4_payload.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    let remainder = chunks.remainder();
    if !remainder.is_empty() {
        sum += (remainder[0] as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    let result = !(sum as u16);
    // RFC 768: For UDP, if the computed checksum is zero, it should be transmitted as all ones (0xffff)
    if protocol == 17 && result == 0 {
        0xffff
    } else {
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_internet_checksum() {
        // Simple test vector
        let data = [0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10, 0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c];
        let cksum = internet_checksum(&data);
        assert_eq!(cksum, 0xb1e6);
    }
}
