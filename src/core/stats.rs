//! Transmission statistics and summary reporting.
use std::sync::atomic::{AtomicUsize, Ordering};

pub struct Statistics {
    pub target: String,
    pub sent: AtomicUsize,
    pub received: AtomicUsize,
}

impl Statistics {
    pub fn new(target: String) -> Self {
        Self {
            target,
            sent: AtomicUsize::new(0),
            received: AtomicUsize::new(0),
        }
    }

    pub fn inc_sent(&self) {
        self.sent.fetch_add(1, Ordering::SeqCst);
    }

    pub fn inc_received(&self) {
        self.received.fetch_add(1, Ordering::SeqCst);
    }

    pub fn print_summary(&self, rtt_min: f64, rtt_avg: f64, rtt_max: f64) {
        let sent = self.sent.load(Ordering::SeqCst);
        let recv = self.received.load(Ordering::SeqCst);

        let loss_pct = if sent > 0 {
            if sent >= recv {
                ((sent - recv) as f64 / sent as f64) * 100.0
            } else {
                0.0
            }
        } else {
            0.0
        };

        println!("\n--- {} hping statistic ---", self.target);
        println!(
            "{} packets transmitted, {} packets received, {:.0}% packet loss",
            sent, recv, loss_pct
        );
        if recv > 0 && rtt_avg > 0.0 {
            println!(
                "round-trip min/avg/max = {:.1}/{:.1}/{:.1} ms",
                rtt_min, rtt_avg, rtt_max
            );
        }
    }
}
