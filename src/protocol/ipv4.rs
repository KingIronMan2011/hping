//! IPv4 header parsing, serialization, and fragmentation.
use std::net::Ipv4Addr;
use super::checksum::internet_checksum;

pub const IP_DF: u16 = 0x4000;
pub const IP_MF: u16 = 0x2000;
pub const IP_OFFSET_MASK: u16 = 0x1FFF;

#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub tos: u8,
    pub total_length: u16,
    pub id: u16,
    pub flags_and_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub options: Vec<u8>,
}

impl Default for Ipv4Header {
    fn default() -> Self {
        Self {
            version: 4,
            ihl: 5,
            tos: 0,
            total_length: 20,
            id: 0,
            flags_and_offset: 0,
            ttl: 64,
            protocol: 6, // TCP default
            checksum: 0,
            src: Ipv4Addr::UNSPECIFIED,
            dst: Ipv4Addr::UNSPECIFIED,
            options: Vec::new(),
        }
    }
}

impl Ipv4Header {
    pub fn parse(buf: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if buf.len() < 20 {
            return Err("IPv4 packet too short");
        }

        let version = (buf[0] >> 4) & 0x0f;
        let ihl = buf[0] & 0x0f;
        if version != 4 {
            return Err("Not an IPv4 packet");
        }
        if (ihl as usize) < 5 {
            return Err("Invalid IHL");
        }

        let header_len = (ihl as usize) * 4;
        if buf.len() < header_len {
            return Err("IPv4 buffer smaller than IHL");
        }

        let tos = buf[1];
        let total_length = u16::from_be_bytes([buf[2], buf[3]]);
        let id = u16::from_be_bytes([buf[4], buf[5]]);
        let flags_and_offset = u16::from_be_bytes([buf[6], buf[7]]);
        let ttl = buf[8];
        let protocol = buf[9];
        let checksum = u16::from_be_bytes([buf[10], buf[11]]);
        let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
        let dst = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);

        let options = if header_len > 20 {
            buf[20..header_len].to_vec()
        } else {
            Vec::new()
        };

        let payload_len = if (total_length as usize) >= header_len && (total_length as usize) <= buf.len() {
            (total_length as usize) - header_len
        } else {
            buf.len() - header_len
        };

        let payload = &buf[header_len..header_len + payload_len];

        Ok((
            Self {
                version,
                ihl,
                tos,
                total_length,
                id,
                flags_and_offset,
                ttl,
                protocol,
                checksum,
                src,
                dst,
                options,
            },
            payload,
        ))
    }

    pub fn serialize(&self, payload_len: usize) -> Vec<u8> {
        let opt_padded_len = (self.options.len() + 3) & !3;
        let ihl = (5 + (opt_padded_len / 4)) as u8;
        let total_length = (ihl as u16 * 4) + (payload_len as u16);

        let mut buf = Vec::with_capacity((ihl as usize) * 4);
        buf.push((self.version << 4) | (ihl & 0x0f));
        buf.push(self.tos);
        buf.extend_from_slice(&total_length.to_be_bytes());
        buf.extend_from_slice(&self.id.to_be_bytes());
        buf.extend_from_slice(&self.flags_and_offset.to_be_bytes());
        buf.push(self.ttl);
        buf.push(self.protocol);
        buf.extend_from_slice(&[0, 0]); // Checksum placeholder
        buf.extend_from_slice(&self.src.octets());
        buf.extend_from_slice(&self.dst.octets());

        // Append options and padding
        buf.extend_from_slice(&self.options);
        while buf.len() < (ihl as usize) * 4 {
            buf.push(0); // NOP / EOL padding
        }

        // Calculate and replace checksum
        let cksum = internet_checksum(&buf);
        buf[10..12].copy_from_slice(&cksum.to_be_bytes());

        buf
    }

    pub fn is_df(&self) -> bool {
        (self.flags_and_offset & IP_DF) != 0
    }

    pub fn is_mf(&self) -> bool {
        (self.flags_and_offset & IP_MF) != 0
    }

    pub fn fragment_offset(&self) -> u16 {
        (self.flags_and_offset & IP_OFFSET_MASK) * 8
    }
}

/// Helper to create fragmented packets if total packet size > mtu
pub fn fragment_packet(
    base_header: Ipv4Header,
    payload: &[u8],
    mtu: usize,
) -> Vec<Vec<u8>> {
    let opt_len = (base_header.options.len() + 3) & !3;
    let header_len = 20 + opt_len;

    if header_len >= mtu || payload.len() + header_len <= mtu {
        // No fragmentation needed
        let mut pkt = base_header.serialize(payload.len());
        pkt.extend_from_slice(payload);
        return vec![pkt];
    }

    let max_frag_payload = (mtu - header_len) & !7; // must be multiple of 8
    if max_frag_payload == 0 {
        let mut pkt = base_header.serialize(payload.len());
        pkt.extend_from_slice(payload);
        return vec![pkt];
    }

    let mut frags = Vec::new();
    let mut offset = 0;

    while offset < payload.len() {
        let remaining = payload.len() - offset;
        let chunk_size = if remaining > max_frag_payload {
            max_frag_payload
        } else {
            remaining
        };

        let is_last = offset + chunk_size >= payload.len();
        let mut flags = ((offset / 8) as u16) & IP_OFFSET_MASK;
        if !is_last {
            flags |= IP_MF;
        }

        let mut frag_hdr = base_header.clone();
        frag_hdr.flags_and_offset = flags;

        let mut frag_bytes = frag_hdr.serialize(chunk_size);
        frag_bytes.extend_from_slice(&payload[offset..offset + chunk_size]);
        frags.push(frag_bytes);

        offset += chunk_size;
    }

    frags
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_and_parse() {
        let mut hdr = Ipv4Header::default();
        hdr.src = Ipv4Addr::new(192, 168, 1, 10);
        hdr.dst = Ipv4Addr::new(192, 168, 1, 1);
        hdr.id = 0x1234;
        hdr.ttl = 64;
        hdr.protocol = 6;

        let payload = b"hello world";
        let mut full_packet = hdr.serialize(payload.len());
        full_packet.extend_from_slice(payload);

        let (parsed_hdr, parsed_payload) = Ipv4Header::parse(&full_packet).unwrap();
        assert_eq!(parsed_hdr.src, hdr.src);
        assert_eq!(parsed_hdr.dst, hdr.dst);
        assert_eq!(parsed_hdr.id, hdr.id);
        assert_eq!(parsed_hdr.protocol, 6);
        assert_eq!(parsed_payload, payload);
    }

    #[test]
    fn test_fragment_packet() {
        let mut hdr = Ipv4Header::default();
        hdr.src = Ipv4Addr::new(10, 0, 0, 1);
        hdr.dst = Ipv4Addr::new(10, 0, 0, 2);

        let large_payload = vec![0x41u8; 100]; // 100 bytes
        // MTU = 40 bytes. Header = 20 bytes. Payload space per fragment = 20 & !7 = 16 bytes.
        let frags = fragment_packet(hdr, &large_payload, 40);
        assert!(frags.len() > 1);

        // Check first fragment has MF set
        let (first_hdr, first_data) = Ipv4Header::parse(&frags[0]).unwrap();
        assert!(first_hdr.is_mf());
        assert_eq!(first_data.len(), 16);
        assert_eq!(first_hdr.fragment_offset(), 0);

        // Check last fragment has MF cleared
        let (last_hdr, _) = Ipv4Header::parse(frags.last().unwrap()).unwrap();
        assert!(!last_hdr.is_mf());
    }
}
