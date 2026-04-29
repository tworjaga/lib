use std::process;

const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                          abcdefghijklmnopqrstuvwxyz\
                          0123456789!@#$%^&*";

fn main() {
    let len = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(16);

    if len == 0 || len > 128 {
        eprintln!("usage: passgen <length>  (1-128)");
        process::exit(1);
    }

    let mut rng = XorShift::seeded();
    let password: String = (0..len)
        .map(|_| CHARSET[rng.next() as usize % CHARSET.len()] as char)
        .collect();

    println!("{}", "─".repeat(len + 4));
    println!("│ {} │", password);
    println!("{}", "─".repeat(len + 4));
}

// Tiny PRNG — no external deps
struct XorShift(u64);

impl XorShift {
    fn seeded() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        Self(seed.wrapping_add(0x9E3779B97F4A7C15))
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}
