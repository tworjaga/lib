use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Read, BufRead, BufReader};
use std::path::Path;

const CHUNK_SIZE: usize = 8192;

fn main() {
    let ioc_path = std::env::args().nth(1)
        .unwrap_or_else(|| {
            eprintln!("usage: ioc_scan <hash_list.txt> [directory]");
            std::process::exit(1);
        });

    let scan_dir = std::env::args().nth(2)
        .unwrap_or_else(|| ".".to_string());

    println!("[*] loading IOCs from: {}", ioc_path);
    let iocs = load_iocs(&ioc_path).unwrap_or_else(|e| {
        eprintln!("[-] failed to load IOCs: {}", e);
        std::process::exit(1);
    });

    println!("[*] loaded {} SHA256 hashes", iocs.len());
    println!("[*] scanning directory: {}", scan_dir);
    println!("{:-<60}", "");

    let mut scanned = 0u64;
    let mut hits = 0u64;

    scan_directory(Path::new(&scan_dir), &iocs, &mut scanned, &mut hits);

    println!("{:-<60}", "");
    println!("[*] scan complete: {} files checked, {} hits", scanned, hits);
}

fn load_iocs(path: &str) -> io::Result<HashSet<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut set = HashSet::new();

    for line in reader.lines() {
        let hash = line?.trim().to_lowercase();
        if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
            set.insert(hash);
        }
    }

    Ok(set)
}

fn scan_directory(
    dir: &Path,
    iocs: &HashSet<String>,
    scanned: &mut u64,
    hits: &mut u64,
) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            println!("[!] cannot read {}: {}", dir.display(), e);
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();

        if path.is_symlink() {
            continue; // avoid loops
        }

        if path.is_dir() {
            scan_directory(&path, iocs, scanned, hits);
        } else if path.is_file() {
            *scanned += 1;
            match hash_file(&path) {
                Ok(hash) => {
                    if iocs.contains(&hash) {
                        *hits += 1;
                        println!(
                            "\x1B[1;31m[ALERT] IOC MATCH\x1B[0m\n  file: {}\n  sha256: {}",
                            path.display(),
                            hash
                        );
                    } else if *scanned % 1000 == 0 {
                        print!("\r[*] scanned {} files...", scanned);
                        io::Write::flush(&mut io::stdout()).unwrap();
                    }
                }
                Err(e) => {
                    println!("[!] cannot hash {}: {}", path.display(), e);
                }
            }
        }
    }
}

fn hash_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; CHUNK_SIZE];

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 { break; }
        hasher.update(&buffer[..n]);
    }

    Ok(hasher.finalize())
}

// minimal SHA-256 implementation — no external crates
struct Sha256 {
    state: [u32; 8],
    buffer: Vec<u8>,
    bit_len: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            buffer: Vec::new(),
            bit_len: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.bit_len += (data.len() as u64) * 8;
        self.buffer.extend_from_slice(data);

        while self.buffer.len() >= 64 {
            let chunk: [u8; 64] = self.buffer[..64].try_into().unwrap();
            self.process_chunk(&chunk);
            self.buffer.drain(..64);
        }
    }

    fn finalize(mut self) -> String {
        let mut msg = self.buffer.clone();
        let len = msg.len();
        msg.push(0x80);

        while (msg.len() % 64) != 56 {
            msg.push(0x00);
        }

        msg.extend_from_slice(&self.bit_len.to_be_bytes());

        for chunk in msg.chunks_exact(64) {
            self.process_chunk(chunk.try_into().unwrap());
        }

        self.state.iter()
            .map(|&w| format!("{:08x}", w))
            .collect()
    }

    fn process_chunk(&mut self, chunk: &[u8; 64]) {
        let k: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        ];

        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4], chunk[i * 4 + 1],
                chunk[i * 4 + 2], chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(k[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}
