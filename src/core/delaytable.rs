//! Thread-safe RTT and sequence tracking table.
use std::sync::Mutex;
use std::time::Instant;

pub const TABLE_SIZE: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketStatus {
    Empty,
    Sent,
    Received,
}

#[derive(Debug, Clone, Copy)]
pub struct DelayEntry {
    pub seq: u32,
    pub src_port: u16,
    pub sent_at: Instant,
    pub status: PacketStatus,
}

impl Default for DelayEntry {
    fn default() -> Self {
        Self {
            seq: 0,
            src_port: 0,
            sent_at: Instant::now(),
            status: PacketStatus::Empty,
        }
    }
}

pub struct DelayTable {
    entries: [DelayEntry; TABLE_SIZE],
    index: usize,
    pub rtt_min: f64,
    pub rtt_max: f64,
    pub rtt_avg: f64,
    avg_counter: usize,
}

impl Default for DelayTable {
    fn default() -> Self {
        Self::new()
    }
}

impl DelayTable {
    pub fn new() -> Self {
        Self {
            entries: [DelayEntry::default(); TABLE_SIZE],
            index: 0,
            rtt_min: 0.0,
            rtt_max: 0.0,
            rtt_avg: 0.0,
            avg_counter: 0,
        }
    }

    pub fn add(&mut self, seq: u32, src_port: u16) {
        let idx = self.index % TABLE_SIZE;
        self.entries[idx] = DelayEntry {
            seq,
            src_port,
            sent_at: Instant::now(),
            status: PacketStatus::Sent,
        };
        self.index = self.index.wrapping_add(1);
    }

    /// Matches a received packet by sequence number and/or destination port (which was our source port).
    /// Returns (is_dup, rtt_ms, matched_seq).
    pub fn match_packet(&mut self, seq: Option<u32>, port: Option<u16>) -> (bool, f64, u32) {
        let mut matched_idx = None;

        if let Some(s) = seq {
            for i in 0..TABLE_SIZE {
                if self.entries[i].status != PacketStatus::Empty && self.entries[i].seq == s {
                    matched_idx = Some(i);
                    break;
                }
            }
        }

        if matched_idx.is_none() {
            if let Some(p) = port {
                for i in 0..TABLE_SIZE {
                    if self.entries[i].status != PacketStatus::Empty && self.entries[i].src_port == p {
                        matched_idx = Some(i);
                        break;
                    }
                }
            }
        }

        if let Some(idx) = matched_idx {
            let entry = &mut self.entries[idx];
            let is_dup = entry.status == PacketStatus::Received;
            entry.status = PacketStatus::Received;

            let elapsed = entry.sent_at.elapsed();
            let rtt_ms = elapsed.as_secs_f64() * 1000.0;
            let matched_seq = entry.seq;

            self.update_stats(rtt_ms);
            (is_dup, rtt_ms, matched_seq)
        } else {
            (false, 0.0, seq.unwrap_or(0))
        }
    }

    fn update_stats(&mut self, rtt_ms: f64) {
        if self.rtt_min == 0.0 || rtt_ms < self.rtt_min {
            self.rtt_min = rtt_ms;
        }
        if self.rtt_max == 0.0 || rtt_ms > self.rtt_max {
            self.rtt_max = rtt_ms;
        }
        self.avg_counter += 1;
        self.rtt_avg = (self.rtt_avg * ((self.avg_counter - 1) as f64) + rtt_ms) / (self.avg_counter as f64);
    }
}

pub struct SharedDelayTable(Mutex<DelayTable>);

impl Default for SharedDelayTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedDelayTable {
    pub fn new() -> Self {
        Self(Mutex::new(DelayTable::new()))
    }

    pub fn add(&self, seq: u32, src_port: u16) {
        if let Ok(mut dt) = self.0.lock() {
            dt.add(seq, src_port);
        }
    }

    pub fn match_packet(&self, seq: Option<u32>, port: Option<u16>) -> (bool, f64, u32) {
        if let Ok(mut dt) = self.0.lock() {
            dt.match_packet(seq, port)
        } else {
            (false, 0.0, 0)
        }
    }

    pub fn stats(&self) -> (f64, f64, f64) {
        if let Ok(dt) = self.0.lock() {
            (dt.rtt_min, dt.rtt_avg, dt.rtt_max)
        } else {
            (0.0, 0.0, 0.0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delay_table_match() {
        let mut dt = DelayTable::new();
        dt.add(1, 12345);
        let (is_dup, rtt, seq) = dt.match_packet(Some(1), None);
        assert!(!is_dup);
        assert_eq!(seq, 1);
        assert!(rtt >= 0.0);

        // Matching again should report dup
        let (is_dup2, _, _) = dt.match_packet(Some(1), None);
        assert!(is_dup2);
    }
}
