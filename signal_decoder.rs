use std::fs::File;
use std::io::{Read, Write};
use std::f64::consts::PI;

const SAMPLE_RATE: f64 = 2_400_000.0;
const CHUNK_SIZE: usize = 65536;

fn main() {
    let input = std::env::args().nth(1)
        .unwrap_or_else(|| {
            eprintln!("usage: sigint_decode <raw_iq_file>");
            eprintln!("       sigint_decode --live");
            std::process::exit(1);
        });

    println!("[*] SIGINT digital decoder initializing...");
    println!("[*] sample rate: {} Hz", SAMPLE_RATE);

    if input == "--live" {
        println!("[*] live mode: reading from stdin (pipe from rtl_sdr)");
        decode_stream(std::io::stdin());
    } else {
        println!("[*] file mode: {}", input);
        let file = File::open(&input).expect("cannot open file");
        decode_stream(file);
    }
}

fn decode_stream<R: Read>(mut reader: R) {
    let mut buf = [0u8; CHUNK_SIZE];
    let mut demod = FskDemod::new(1200.0, 2200.0); // Bell 202 / AFSK
    let mut ask_demod = AskDemod::new(1000.0);
    let mut psk_demod = PskDemod::new(1200.0);

    let mut total_samples = 0u64;

    loop {
        match reader.read_exact(&mut buf) {
            Ok(()) => {},
            Err(_) => break,
        }

        let samples = bytes_to_iq(&buf);

        // run multiple demodulators in parallel on same stream
        let fsk_bits = demod.process(&samples);
        let ask_bits = ask_demod.process(&samples);
        let psk_bits = psk_demod.process(&samples);

        // frame detection and extraction
        if let Some(frame) = detect_ax25(&fsk_bits) {
            println!(
                "\x1B[1;32m[AX.25/AFSK]\x1B[0m  \
                 src: {}  dst: {}  \
                 control: 0x{:02X}  \
                 payload: {} bytes",
                frame.src, frame.dst,
                frame.control,
                frame.payload.len()
            );
            if !frame.payload.is_empty() {
                println!("  data: {}", hex_dump(&frame.payload));
            }
        }

        if let Some(frame) = detect_morse(&ask_bits) {
            println!(
                "\x1B[1;33m[CW/MORSE]\x1B[0m  freq: {:.0} Hz  text: {}",
                frame.freq, frame.text
            );
        }

        if let Some(frame) = detect_psk31(&psk_bits) {
            println!(
                "\x1B[1;36m[PSK31]\x1B[0m  text: {}",
                frame.text
            );
        }

        // raw bitstream for unknown signals
        if fsk_bits.len() > 100 {
            analyze_unknown(&fsk_bits, total_samples);
        }

        total_samples += samples.len() as u64;
    }

    println!("[*] processed {} samples", total_samples);
}

fn bytes_to_iq(bytes: &[u8]) -> Vec<Complex> {
    bytes.chunks_exact(2)
        .map(|chunk| {
            let i = (chunk[0] as f64 - 127.5) / 127.5;
            let q = (chunk[1] as f64 - 127.5) / 127.5;
            Complex { re: i, im: q }
        })
        .collect()
}

#[derive(Clone, Copy)]
struct Complex {
    re: f64,
    im: f64,
}

impl Complex {
    fn magnitude(&self) -> f64 {
        (self.re * self.re + self.im * self.im).sqrt()
    }

    fn phase(&self) -> f64 {
        self.im.atan2(self.re)
    }

    fn conj(&self) -> Self {
        Self { re: self.re, im: -self.im }
    }
}

struct FskDemod {
    mark_freq: f64,
    space_freq: f64,
    mark_phase: f64,
    space_phase: f64,
    samples_per_bit: usize,
    sample_count: usize,
    mark_acc: f64,
    space_acc: f64,
    bit_buffer: Vec<u8>,
    agc_level: f64,
}

impl FskDemod {
    fn new(mark_hz: f64, space_hz: f64) -> Self {
        let baud = 1200.0;
        Self {
            mark_freq: mark_hz,
            space_freq: space_hz,
            mark_phase: 0.0,
            space_phase: 0.0,
            samples_per_bit: (SAMPLE_RATE / baud) as usize,
            sample_count: 0,
            mark_acc: 0.0,
            space_acc: 0.0,
            bit_buffer: Vec::new(),
            agc_level: 1.0,
        }
    }

    fn process(&mut self, samples: &[Complex]) -> Vec<u8> {
        let mut bits = Vec::new();

        for s in samples {
            // correlate against mark and space frequencies
            let mark_i = s.re * self.mark_phase.cos() + s.im * self.mark_phase.sin();
            let space_i = s.re * self.space_phase.cos() + s.im * self.space_phase.sin();

            self.mark_acc += mark_i * mark_i;
            self.space_acc += space_i * space_i;

            // update NCO phases
            self.mark_phase += 2.0 * PI * self.mark_freq / SAMPLE_RATE;
            self.space_phase += 2.0 * PI * self.space_freq / SAMPLE_RATE;

            self.sample_count += 1;

            if self.sample_count >= self.samples_per_bit {
                // AGC
                let total = self.mark_acc + self.space_acc;
                self.agc_level = self.agc_level * 0.99 + total * 0.01;

                let bit = if self.mark_acc > self.space_acc { 1 } else { 0 };
                bits.push(bit);

                self.mark_acc = 0.0;
                self.space_acc = 0.0;
                self.sample_count = 0;
            }
        }

        // NRZI decode
        let mut nrzi = Vec::new();
        let mut last = 1u8;
        for &bit in &bits {
            if bit == 0 {
                last = 1 - last;
            }
            nrzi.push(last);
        }

        nrzi
    }
}

struct AskDemod {
    carrier_freq: f64,
    phase: f64,
    sample_count: usize,
    energy_acc: f64,
    samples_per_symbol: usize,
    threshold: f64,
    bit_buffer: Vec<u8>,
}

impl AskDemod {
    fn new(carrier_hz: f64) -> Self {
        Self {
            carrier_freq: carrier_hz,
            phase: 0.0,
            sample_count: 0,
            energy_acc: 0.0,
            samples_per_symbol: (SAMPLE_RATE / 100.0) as usize, // 100 baud default
            threshold: 0.1,
            bit_buffer: Vec::new(),
        }
    }

    fn process(&mut self, samples: &[Complex]) -> Vec<u8> {
        let mut bits = Vec::new();

        for s in samples {
            let carrier = s.re * self.phase.cos() + s.im * self.phase.sin();
            self.energy_acc += carrier * carrier;
            self.phase += 2.0 * PI * self.carrier_freq / SAMPLE_RATE;
            self.sample_count += 1;

            if self.sample_count >= self.samples_per_symbol {
                let bit = if self.energy_acc > self.threshold { 1 } else { 0 };
                bits.push(bit);
                self.energy_acc = 0.0;
                self.sample_count = 0;
            }
        }

        bits
    }
}

struct PskDemod {
    carrier_freq: f64,
    phase: f64,
    last_phase: f64,
    sample_count: usize,
    samples_per_symbol: usize,
    bit_buffer: Vec<u8>,
}

impl PskDemod {
    fn new(carrier_hz: f64) -> Self {
        Self {
            carrier_freq: carrier_hz,
            phase: 0.0,
            last_phase: 0.0,
            sample_count: 0,
            samples_per_symbol: (SAMPLE_RATE / 31.25) as usize, // PSK31
            bit_buffer: Vec::new(),
        }
    }

    fn process(&mut self, samples: &[Complex]) -> Vec<u8> {
        let mut bits = Vec::new();

        for s in samples {
            // Costas loop-ish phase detection
            let i = s.re * self.phase.cos() + s.im * self.phase.sin();
            let q = -s.re * self.phase.sin() + s.im * self.phase.cos();

            self.phase += 2.0 * PI * self.carrier_freq / SAMPLE_RATE;
            self.sample_count += 1;

            if self.sample_count >= self.samples_per_symbol {
                let current_phase = q.atan2(i);
                let delta = phase_diff(current_phase, self.last_phase);

                let bit = if delta.abs() > PI / 2.0 { 1 } else { 0 };
                bits.push(bit);

                self.last_phase = current_phase;
                self.sample_count = 0;
            }
        }

        bits
    }
}

fn phase_diff(a: f64, b: f64) -> f64 {
    let mut d = a - b;
    while d > PI { d -= 2.0 * PI; }
    while d < -PI { d += 2.0 * PI; }
    d
}

#[derive(Debug)]
struct Ax25Frame {
    src: String,
    dst: String,
    control: u8,
    payload: Vec<u8>,
}

fn detect_ax25(bits: &[u8]) -> Option<Ax25Frame> {
    // look for flag sequence 0x7E (01111110)
    let flag: Vec<u8> = vec![0, 1, 1, 1, 1, 1, 1, 0];

    let mut start = None;
    for i in 0..bits.len().saturating_sub(8) {
        if &bits[i..i+8] == flag.as_slice() {
            start = Some(i + 8);
            break;
        }
    }

    let start = start?;

    // dest addr (7 bytes) + src addr (7 bytes) + control (1) + pid (1) + info
    if start + 16 > bits.len() {
        return None;
    }

    let dest = decode_callsign(&bits[start..start+56]);
    let src = decode_callsign(&bits[start+56..start+112]);
    let control = bits_to_byte(&bits[start+112..start+120]);

    let payload_start = start + 128; // skip PID
    let mut payload = Vec::new();

    for chunk in bits[payload_start..].chunks(8) {
        if chunk.len() < 8 { break; }
        if chunk == flag.as_slice() { break; } // end flag
        payload.push(bits_to_byte(chunk));
    }

    Some(Ax25Frame { src, dst: dest, control, payload })
}

fn decode_callsign(bits: &[u8]) -> String {
    let mut chars = Vec::new();
    for chunk in bits.chunks(8) {
        if chunk.len() < 8 { break; }
        let byte = bits_to_byte(chunk) >> 1; // AX.25 shifts left
        if byte == 0x40 { break; } // @ padding
        chars.push((byte as char).to_string());
    }
    chars.join("").trim().to_string()
}

fn bits_to_byte(bits: &[u8]) -> u8 {
    let mut b = 0u8;
    for (i, &bit) in bits.iter().enumerate().take(8) {
        b |= bit << (7 - i);
    }
    b
}

#[derive(Debug)]
struct MorseFrame {
    freq: f64,
    text: String,
}

fn detect_morse(bits: &[u8]) -> Option<MorseFrame> {
    // simple threshold-based morse detection
    if bits.len() < 50 { return None; }

    let mut symbols = Vec::new();
    let mut count = 0;
    let mut last = bits[0];

    for &bit in bits {
        if bit == last {
            count += 1;
        } else {
            symbols.push((last, count));
            count = 1;
            last = bit;
        }
    }
    symbols.push((last, count));

    // classify dit/dah/space
    let avg_mark: f64 = symbols.iter()
        .filter(|(s, _)| *s == 1)
        .map(|(_, c)| *c as f64)
        .sum::<f64>() / symbols.iter().filter(|(s, _)| *s == 1).count().max(1) as f64;

    let mut morse = String::new();
    for &(sym, len) in &symbols {
        if sym == 1 {
            if len as f64 < avg_mark * 1.5 {
                morse.push('.');
            } else {
                morse.push('-');
            }
        } else {
            if len as f64 > avg_mark * 3.0 {
                morse.push(' ');
            }
        }
    }

    let text = morse_to_ascii(&morse);
    if text.len() > 3 {
        Some(MorseFrame { freq: 1000.0, text })
    } else {
        None
    }
}

fn morse_to_ascii(morse: &str) -> String {
    let table: std::collections::HashMap<&str, char> = [
        (".-", 'A'), ("-...", 'B'), ("-.-.", 'C'), ("-..", 'D'), (".", 'E'),
        ("..-.", 'F'), ("--.", 'G'), ("....", 'H'), ("..", 'I'), (".---", 'J'),
        ("-.-", 'K'), (".-..", 'L'), ("--", 'M'), ("-.", 'N'), ("---", 'O'),
        (".--.", 'P'), ("--.-", 'Q'), (".-.", 'R'), ("...", 'S'), ("-", 'T'),
        ("..-", 'U'), ("...-", 'V'), (".--", 'W'), ("-..-", 'X'), ("-.--", 'Y'),
        ("--..", 'Z'), ("-----", '0'), (".----", '1'), ("..---", '2'),
        ("...--", '3'), ("....-", '4'), (".....", '5'), ("-....", '6'),
        ("--...", '7'), ("---..", '8'), ("----.", '9'),
    ].iter().cloned().collect();

    morse.split(' ')
        .filter_map(|s| table.get(s).copied())
        .collect()
}

#[derive(Debug)]
struct Psk31Frame {
    text: String,
}

fn detect_psk31(bits: &[u8]) -> Option<Psk31Frame> {
    // Varicode decode
    if bits.len() < 20 { return None; }

    let mut text = String::new();
    let mut i = 0;

    while i < bits.len() {
        // look for double-zero separator
        if i + 1 < bits.len() && bits[i] == 0 && bits[i + 1] == 0 {
            i += 2;
            continue;
        }

        // extract varicode character (variable length, ends with 00)
        let mut char_bits = Vec::new();
        while i < bits.len() - 1 {
            if bits[i] == 0 && bits[i + 1] == 0 {
                i += 2;
                break;
            }
            char_bits.push(bits[i]);
            i += 1;
        }

        if let Some(c) = varicode_decode(&char_bits) {
            text.push(c);
        }
    }

    if text.len() > 3 {
        Some(Psk31Frame { text })
    } else {
        None
    }
}

fn varicode_decode(bits: &[u8]) -> Option<char> {
    let table: std::collections::HashMap<Vec<u8>, char> = [
        (vec![1,0,1,0,1,0,1,1], ' '),
        (vec![1,1,1,0,1,1,1,0,1], 'E'),
        (vec![1,0,1,1,1,0,1], 'T'),
        (vec![1,0,1,0,1,1,1], 'A'),
        (vec![1,1,1,0,1,0,1], 'O'),
        (vec![1,1,1,0,1,1,1], 'I'),
        (vec![1,0,1,1,1,0,1,1], 'N'),
        (vec![1,1,1,0,1,0,1,0,1], 'S'),
        (vec![1,0,1,0,1,0,1,1,1], 'H'),
        (vec![1,1,1,0,1,0,1,1], 'R'),
    ].iter().cloned().collect();

    table.get(bits).copied()
}

fn analyze_unknown(bits: &[u8], sample_offset: u64) {
    // entropy analysis for unknown signals
    let ones = bits.iter().filter(|&&b| b == 1).count();
    let zeros = bits.len() - ones;
    let ratio = ones as f64 / bits.len() as f64;

    // run length distribution
    let mut runs = Vec::new();
    let mut count = 1;
    for w in bits.windows(2) {
        if w[0] == w[1] {
            count += 1;
        } else {
            runs.push(count);
            count = 1;
        }
    }
    runs.push(count);

    let avg_run = runs.iter().sum::<usize>() as f64 / runs.len() as f64;

    println!(
        "\x1B[2m[UNKNOWN]  offset: {}  bits: {}  \
         entropy: {:.3}  ones: {:.1}%  avg_run: {:.1}\x1B[0m",
        sample_offset,
        bits.len(),
        -ratio * ratio.log2() - (1.0-ratio) * (1.0-ratio).log2(),
        ratio * 100.0,
        avg_run
    );
}

fn hex_dump(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .chunks(16)
        .map(|c| c.join(" "))
        .collect::<Vec<_>>()
        .join("\n           ")
}
