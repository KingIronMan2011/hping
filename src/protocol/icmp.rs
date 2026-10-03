//! ICMP header parsing, message types, and error packet unwrapping.
use super::checksum::internet_checksum;

pub const ICMP_ECHOREPLY: u8 = 0;
pub const ICMP_DEST_UNREACH: u8 = 3;
pub const ICMP_ECHO: u8 = 8;
pub const ICMP_TIME_EXCEEDED: u8 = 11;
pub const ICMP_TIMESTAMP: u8 = 13;
pub const ICMP_TIMESTAMPREPLY: u8 = 14;
pub const ICMP_ADDRESS: u8 = 17;
pub const ICMP_ADDRESSREPLY: u8 = 18;

#[derive(Debug, Clone)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub rest_of_header: [u8; 4],
}

impl Default for IcmpHeader {
    fn default() -> Self {
        Self {
            icmp_type: ICMP_ECHO,
            code: 0,
            checksum: 0,
            rest_of_header: [0; 4],
        }
    }
}

impl IcmpHeader {
    pub fn echo_request(id: u16, seq: u16) -> Self {
        let mut rest = [0u8; 4];
        rest[0..2].copy_from_slice(&id.to_be_bytes());
        rest[2..4].copy_from_slice(&seq.to_be_bytes());
        Self {
            icmp_type: ICMP_ECHO,
            code: 0,
            checksum: 0,
            rest_of_header: rest,
        }
    }

    pub fn timestamp_request(id: u16, seq: u16) -> Self {
        let mut rest = [0u8; 4];
        rest[0..2].copy_from_slice(&id.to_be_bytes());
        rest[2..4].copy_from_slice(&seq.to_be_bytes());
        Self {
            icmp_type: ICMP_TIMESTAMP,
            code: 0,
            checksum: 0,
            rest_of_header: rest,
        }
    }

    pub fn address_mask_request(id: u16, seq: u16) -> Self {
        let mut rest = [0u8; 4];
        rest[0..2].copy_from_slice(&id.to_be_bytes());
        rest[2..4].copy_from_slice(&seq.to_be_bytes());
        Self {
            icmp_type: ICMP_ADDRESS,
            code: 0,
            checksum: 0,
            rest_of_header: rest,
        }
    }

    pub fn id(&self) -> u16 {
        u16::from_be_bytes([self.rest_of_header[0], self.rest_of_header[1]])
    }

    pub fn seq(&self) -> u16 {
        u16::from_be_bytes([self.rest_of_header[2], self.rest_of_header[3]])
    }

    pub fn parse(buf: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if buf.len() < 8 {
            return Err("ICMP packet too short");
        }

        let icmp_type = buf[0];
        let code = buf[1];
        let checksum = u16::from_be_bytes([buf[2], buf[3]]);
        let mut rest_of_header = [0u8; 4];
        rest_of_header.copy_from_slice(&buf[4..8]);

        Ok((
            Self {
                icmp_type,
                code,
                checksum,
                rest_of_header,
            },
            &buf[8..],
        ))
    }

    pub fn serialize(&self, payload: &[u8], bad_cksum: bool) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + payload.len());
        buf.push(self.icmp_type);
        buf.push(self.code);
        buf.extend_from_slice(&[0, 0]); // Checksum placeholder
        buf.extend_from_slice(&self.rest_of_header);
        buf.extend_from_slice(payload);

        let cksum = if bad_cksum {
            0xbeef
        } else {
            internet_checksum(&buf)
        };

        buf[2..4].copy_from_slice(&cksum.to_be_bytes());
        buf
    }
}

pub fn icmp_unreach_description(code: u8) -> &'static str {
    match code {
        0 => "Network Unreachable",
        1 => "Host Unreachable",
        2 => "Protocol Unreachable",
        3 => "Port Unreachable",
        4 => "Fragmentation Needed and DF set",
        5 => "Source Route Failed",
        6 => "Destination Network Unknown",
        7 => "Destination Host Unknown",
        8 => "Source Host Isolated",
        9 => "Destination Network Administratively Prohibited",
        10 => "Destination Host Administratively Prohibited",
        11 => "Network Unreachable for TOS",
        12 => "Host Unreachable for TOS",
        13 => "Packet Filtered",
        14 => "Precedence Violation",
        15 => "Precedence Cutoff",
        _ => "Unknown Unreachable Code",
    }
}

pub fn icmp_time_exceeded_description(code: u8) -> &'static str {
    match code {
        0 => "TTL 0 during transit",
        1 => "TTL 0 during reassembly",
        _ => "Time Exceeded (unknown code)",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_echo_serialize_and_parse() {
        let echo = IcmpHeader::echo_request(0x1234, 42);
        let payload = b"ping data 123";
        let bytes = echo.serialize(payload, false);

        let (parsed_hdr, parsed_payload) = IcmpHeader::parse(&bytes).unwrap();
        assert_eq!(parsed_hdr.icmp_type, ICMP_ECHO);
        assert_eq!(parsed_hdr.code, 0);
        assert_eq!(parsed_hdr.id(), 0x1234);
        assert_eq!(parsed_hdr.seq(), 42);
        assert_eq!(parsed_payload, payload);
    }

    #[test]
    fn test_icmp_unreach_messages() {
        assert_eq!(icmp_unreach_description(0), "Network Unreachable");
        assert_eq!(icmp_unreach_description(3), "Port Unreachable");
        assert_eq!(icmp_time_exceeded_description(0), "TTL 0 during transit");
    }
}
