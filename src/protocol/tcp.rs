//! TCP header parsing, flags, and options.
use std::net::Ipv4Addr;
use super::checksum::pseudo_header_checksum;

pub const TH_FIN: u8  = 0x01;
pub const TH_SYN: u8  = 0x02;
pub const TH_RST: u8  = 0x04;
pub const TH_PUSH: u8 = 0x08;
pub const TH_ACK: u8  = 0x10;
pub const TH_URG: u8  = 0x20;
pub const TH_X: u8    = 0x40; // Xmas 0x40 flag
pub const TH_Y: u8    = 0x80; // Ymas 0x80 flag

#[derive(Debug, Clone)]
pub struct TcpHeader {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub data_offset: u8, // in 4-byte words (usually 5 without options)
    pub flags: u8,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
    pub options: Vec<u8>,
}

impl Default for TcpHeader {
    fn default() -> Self {
        Self {
            sport: 0,
            dport: 0,
            seq: 0,
            ack: 0,
            data_offset: 5,
            flags: 0,
            window_size: 64,
            checksum: 0,
            urgent_ptr: 0,
            options: Vec::new(),
        }
    }
}

impl TcpHeader {
    pub fn parse(buf: &[u8]) -> Result<(Self, &[u8]), &'static str> {
        if buf.len() < 20 {
            return Err("TCP header too short");
        }

        let sport = u16::from_be_bytes([buf[0], buf[1]]);
        let dport = u16::from_be_bytes([buf[2], buf[3]]);
        let seq = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let ack = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let data_offset = (buf[12] >> 4) & 0x0f;
        let flags = buf[13];
        let window_size = u16::from_be_bytes([buf[14], buf[15]]);
        let checksum = u16::from_be_bytes([buf[16], buf[17]]);
        let urgent_ptr = u16::from_be_bytes([buf[18], buf[19]]);

        let header_len = (data_offset as usize) * 4;
        if header_len < 20 {
            return Err("TCP data offset too small");
        }
        if buf.len() < header_len {
            return Err("TCP buffer smaller than data offset");
        }

        let options = if header_len > 20 {
            buf[20..header_len].to_vec()
        } else {
            Vec::new()
        };

        let payload = &buf[header_len..];

        Ok((
            Self {
                sport,
                dport,
                seq,
                ack,
                data_offset,
                flags,
                window_size,
                checksum,
                urgent_ptr,
                options,
            },
            payload,
        ))
    }

    /// Serializes the TCP segment (header + payload) and calculates pseudo-header checksum.
    pub fn serialize(
        &self,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        payload: &[u8],
        bad_cksum: bool,
    ) -> Vec<u8> {
        let opt_padded_len = (self.options.len() + 3) & !3;
        let offset = if self.data_offset > 0 {
            self.data_offset
        } else {
            (5 + (opt_padded_len / 4)) as u8
        };

        let mut buf = Vec::with_capacity((offset as usize * 4) + payload.len());
        buf.extend_from_slice(&self.sport.to_be_bytes());
        buf.extend_from_slice(&self.dport.to_be_bytes());
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.extend_from_slice(&self.ack.to_be_bytes());
        buf.push((offset << 4) & 0xf0);
        buf.push(self.flags);
        buf.extend_from_slice(&self.window_size.to_be_bytes());
        buf.extend_from_slice(&[0, 0]); // Checksum placeholder
        buf.extend_from_slice(&self.urgent_ptr.to_be_bytes());

        // Options
        buf.extend_from_slice(&self.options);
        while buf.len() < (offset as usize) * 4 {
            buf.push(0);
        }

        // Payload
        buf.extend_from_slice(payload);

        let cksum = if bad_cksum {
            0xbeef
        } else {
            pseudo_header_checksum(src, dst, 6, &buf)
        };

        buf[16..18].copy_from_slice(&cksum.to_be_bytes());

        buf
    }

    /// Formats flags into human-readable representation like "SA", "RA", "FPU", etc.
    pub fn flags_string(&self) -> String {
        let mut s = String::new();
        if self.flags & TH_RST != 0 { s.push('R'); }
        if self.flags & TH_SYN != 0 { s.push('S'); }
        if self.flags & TH_ACK != 0 { s.push('A'); }
        if self.flags & TH_FIN != 0 { s.push('F'); }
        if self.flags & TH_PUSH != 0 { s.push('P'); }
        if self.flags & TH_URG != 0 { s.push('U'); }
        if self.flags & TH_X != 0 { s.push('X'); }
        if self.flags & TH_Y != 0 { s.push('Y'); }
        if s.is_empty() {
            "none".to_string()
        } else {
            s
        }
    }

    /// Extracts TCP timestamp option (TSval, TSecr) if present.
    pub fn extract_timestamp(&self) -> Option<(u32, u32)> {
        let mut i = 0;
        while i < self.options.len() {
            match self.options[i] {
                0 => break, // End of options
                1 => i += 1, // NOP
                8 => {
                    // Timestamp option: Kind (1) + Length (1) + TSval (4) + TSecr (4) = 10
                    if i + 1 < self.options.len() {
                        let len = self.options[i + 1] as usize;
                        if len == 10 && i + 10 <= self.options.len() {
                            let tsval = u32::from_be_bytes([
                                self.options[i + 2],
                                self.options[i + 3],
                                self.options[i + 4],
                                self.options[i + 5],
                            ]);
                            let tsecr = u32::from_be_bytes([
                                self.options[i + 6],
                                self.options[i + 7],
                                self.options[i + 8],
                                self.options[i + 9],
                            ]);
                            return Some((tsval, tsecr));
                        }
                    }
                    return None;
                }
                _ => {
                    if i + 1 < self.options.len() {
                        let len = self.options[i + 1] as usize;
                        if len == 0 { break; }
                        i += len;
                    } else {
                        break;
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_serialize_and_parse() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);

        let mut tcp = TcpHeader::default();
        tcp.sport = 12345;
        tcp.dport = 80;
        tcp.seq = 1000;
        tcp.ack = 2000;
        tcp.flags = TH_SYN | TH_ACK;
        tcp.window_size = 8192;

        let payload = b"GET / HTTP/1.0\r\n\r\n";
        let bytes = tcp.serialize(src, dst, payload, false);

        let (parsed_hdr, parsed_payload) = TcpHeader::parse(&bytes).unwrap();
        assert_eq!(parsed_hdr.sport, 12345);
        assert_eq!(parsed_hdr.dport, 80);
        assert_eq!(parsed_hdr.seq, 1000);
        assert_eq!(parsed_hdr.ack, 2000);
        assert_eq!(parsed_hdr.flags, TH_SYN | TH_ACK);
        assert_eq!(parsed_hdr.flags_string(), "SA");
        assert_eq!(parsed_hdr.window_size, 8192);
        assert_eq!(parsed_payload, payload);
    }

    #[test]
    fn test_tcp_flags_formatting() {
        let mut tcp = TcpHeader::default();
        assert_eq!(tcp.flags_string(), "none");

        tcp.flags = TH_SYN;
        assert_eq!(tcp.flags_string(), "S");

        tcp.flags = TH_RST | TH_ACK;
        assert_eq!(tcp.flags_string(), "RA");

        tcp.flags = TH_FIN | TH_PUSH | TH_URG;
        assert_eq!(tcp.flags_string(), "FPU");

        tcp.flags = TH_X | TH_Y;
        assert_eq!(tcp.flags_string(), "XY");
    }
}
