use std::io::{self, Write};
use std::thread::sleep;
use std::time::Duration;

const W: usize = 80;
const H: usize = 24;
const BANDS: usize = 40;

fn main() {
    print!("\x1B[2J\x1B[?25l");

    let mut heights = [0.0f64; BANDS];
    let mut targets = [0.0f64; BANDS];
    let mut seed = 0xBEEFu64;

    let mut rand = || {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        (seed >> 33) as u32
    };

    loop {
        // generate new targets with some continuity
        for i in 0..BANDS {
            let noise = (rand() % 100) as f64 / 100.0;
            let freq = i as f64 * 0.3;
            let beat = ((seed as f64 * 0.001).sin() * 0.5 + 0.5) * (i == BANDS / 4 || i == BANDS * 3 / 4) as i32 as f64;
            targets[i] = (noise * (1.0 + freq.sin() * 0.3) + beat * 0.4).min(1.0) * (H - 2) as f64;
        }

        // smooth interpolation
        for i in 0..BANDS {
            heights[i] += (targets[i] - heights[i]) * 0.15;
        }

        let mut buf = vec![vec![0u8; W]; H];

        // draw bars
        for (i, &h) in heights.iter().enumerate() {
            let bar_w = W / BANDS;
            let x_start = i * bar_w;
            let bar_h = h as usize;

            for bx in 0..bar_w.saturating_sub(1) {
                let x = x_start + bx;
                if x >= W { continue; }
                for y in 0..bar_h {
                    let gy = H - 1 - y;
                    let intensity = (y as f64 / H as f64 * 255.0) as u8;
                    buf[gy][x] = intensity.max(buf[gy][x]);
                }
            }
        }

        // render
        let mut out = String::with_capacity((W + 40) * H);
        out.push_str("\x1B[H");
        for row in &buf {
            for &b in row {
                if b == 0 {
                    out.push(' ');
                } else {
                    let chars = " ▁▂▃▄▅▆▇█";
                    let idx = (b as usize * (chars.len() - 1)) / 255;
                    let c = chars.chars().nth(idx).unwrap();
                    let col = if b > 200 { 46 } else if b > 150 { 82 } else if b > 100 { 118 } else if b > 50 { 154 } else { 190 };
                    out.push_str(&format!("\x1B[38;5;{}m{}\x1B[0m", col, c));
                }
            }
            out.push('\n');
        }
        print!("{}", out);
        io::stdout().flush().unwrap();
        sleep(Duration::from_millis(30));
    }
}
