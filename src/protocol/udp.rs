//! UDP header parsing and serialization.
use std::net::Ipv4Addr;
use super::checksum::pseudo_header_checksum;

#[derive(Debug, Clone, Default)]
pub struct UdpHeader {
    pub sport: u16,
    pub dport: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UdpHeader {
    pub fn parse(buf: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if buf.len() < 8 {
            return Err("UDP header too short");
        }

        let sport = u16::from_be_bytes([buf[0], buf[1]]);
        let dport = u16::from_be_bytes([buf[2], buf[3]]);
        let length = u16::from_be_bytes([buf[4], buf[5]]);
        let checksum = u16::from_be_bytes([buf[6], buf[7]]);

        let payload_len = if (length as usize) >= 8 && (length as usize) <= buf.len() {
            (length as usize) - 8
        } else {
            buf.len() - 8
        };

        Ok((
            Self {
                sport,
                dport,
                length,
                checksum,
            },
            &buf[8..8 + payload_len],
        ))
    }

    pub fn serialize(
        &self,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        payload: &[u8],
        bad_cksum: bool,
    ) -> Vec<u8> {
        let total_len = 8 + payload.len();
        let mut buf = Vec::with_capacity(total_len);

        buf.extend_from_slice(&self.sport.to_be_bytes());
        buf.extend_from_slice(&self.dport.to_be_bytes());
        buf.extend_from_slice(&(total_len as u16).to_be_bytes());
        buf.extend_from_slice(&[0, 0]); // Checksum placeholder
        buf.extend_from_slice(payload);

        let cksum = if bad_cksum {
            0xbeef
        } else {
            pseudo_header_checksum(src, dst, 17, &buf)
        };

        buf[6..8].copy_from_slice(&cksum.to_be_bytes());
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_serialize_and_parse() {
        let src = Ipv4Addr::new(192, 168, 1, 50);
        let dst = Ipv4Addr::new(192, 168, 1, 1);

        let udp = UdpHeader {
            sport: 5353,
            dport: 53,
            length: 12,
            checksum: 0,
        };

        let payload = b"test";
        let bytes = udp.serialize(src, dst, payload, false);

        let (parsed_hdr, parsed_payload) = UdpHeader::parse(&bytes).unwrap();
        assert_eq!(parsed_hdr.sport, 5353);
        assert_eq!(parsed_hdr.dport, 53);
        assert_eq!(parsed_hdr.length, 12);
        assert_eq!(parsed_payload, payload);
    }
}
