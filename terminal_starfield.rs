use std::io::{self, Write};
use std::thread::sleep;
use std::time::Duration;

const W: usize = 80;
const H: usize = 24;
const N: usize = 200;

fn main() {
    print!("\x1B[2J\x1B[?25l");

    let mut sx = [0.0f64; N];
    let mut sy = [0.0f64; N];
    let mut sz = [0.0f64; N];

    let mut seed = 0xDEADC0DEu64;
    let mut rand = || {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        (seed >> 33) as u32
    };

    for i in 0..N {
        sx[i] = (rand() % W as u32) as f64 - W as f64 / 2.0;
        sy[i] = (rand() % H as u32) as f64 - H as f64 / 2.0;
        sz[i] = (rand() % 1000) as f64 / 100.0 + 0.5;
    }

    loop {
        let mut buf = vec![vec![0u8; W]; H];

        for i in 0..N {
            sz[i] -= 0.08;
            if sz[i] < 0.1 {
                sz[i] = 10.0;
                sx[i] = (rand() % W as u32) as f64 - W as f64 / 2.0;
                sy[i] = (rand() % H as u32) as f64 - H as f64 / 2.0;
            }

            let x = ((sx[i] / sz[i]) * 8.0 + W as f64 / 2.0) as i32;
            let y = ((sy[i] / sz[i]) * 4.0 + H as f64 / 2.0) as i32;

            if x >= 0 && x < W as i32 && y >= 0 && y < H as i32 {
                let brightness = ((1.0 - sz[i] / 10.0) * 255.0) as u8;
                let ux = x as usize;
                let uy = y as usize;
                if brightness > buf[uy][ux] {
                    buf[uy][ux] = brightness;
                }
            }
        }

        let mut out = String::with_capacity((W + 30) * H);
        out.push_str("\x1B[H");
        for row in &buf {
            for &b in row {
                if b == 0 {
                    out.push(' ');
                } else {
                    let chars = "·∙•●";
                    let idx = (b as usize * (chars.len() - 1)) / 255;
                    let c = chars.chars().nth(idx).unwrap();
                    let col = if b > 200 { 15 } else if b > 120 { 250 } else if b > 60 { 245 } else { 240 };
                    out.push_str(&format!("\x1B[38;5;{}m{}\x1B[0m", col, c));
                }
            }
            out.push('\n');
        }
        print!("{}", out);
        io::stdout().flush().unwrap();
        sleep(Duration::from_millis(16));
    }
}
