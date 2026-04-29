use std::io::{self, Write};
use std::thread::sleep;
use std::time::Duration;

const W: usize = 80;
const H: usize = 24;
const N: usize = 150;

fn main() {
    print!("\x1B[2J\x1B[?25l");
    let mut px = [0.0f64; N];
    let mut py = [0.0f64; N];
    let mut vx = [0.0f64; N];
    let mut vy = [0.0f64; N];
    let mut life = [0u8; N];

    let mut seed = 0xCAFEBABEu64;
    let mut rand = || {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        (seed >> 33) as u32
    };

    for i in 0..N {
        px[i] = (rand() % W as u32) as f64;
        py[i] = (rand() % (H / 2) as u32) as f64;
        vx[i] = ((rand() % 100) as f64 - 50.0) / 200.0;
        vy[i] = (rand() % 50) as f64 / -100.0;
        life[i] = (rand() % 200 + 55) as u8;
    }

    loop {
        let mut buf = vec![vec![(0u8, 0u8); W]; H];

        for i in 0..N {
            vy[i] += 0.015;
            px[i] += vx[i];
            py[i] += vy[i];

            if px[i] < 0.0 || px[i] >= W as f64 - 1.0 {
                vx[i] = -vx[i] * 0.8;
                px[i] = px[i].clamp(0.0, W as f64 - 1.1);
            }
            if py[i] >= H as f64 - 1.0 {
                vy[i] = -vy[i] * 0.6;
                vx[i] *= 0.95;
                py[i] = H as f64 - 1.1;
                if vy[i].abs() < 0.1 {
                    py[i] = (rand() % (H / 3) as u32) as f64;
                    vy[i] = 0.0;
                    life[i] = (rand() % 150 + 100) as u8;
                }
            }

            let gx = px[i] as usize;
            let gy = py[i] as usize;
            if gy < H && gx < W {
                let speed = (vx[i] * vx[i] + vy[i] * vy[i]).sqrt();
                let heat = (speed * 800.0).min(255.0) as u8;
                buf[gy][gx] = (life[i], heat);
            }

            life[i] = life[i].saturating_sub(1);
            if life[i] == 0 {
                px[i] = (rand() % W as u32) as f64;
                py[i] = 0.0;
                vx[i] = ((rand() % 100) as f64 - 50.0) / 300.0;
                vy[i] = (rand() % 30) as f64 / 100.0;
                life[i] = (rand() % 200 + 100) as u8;
            }
        }

        let mut out = String::with_capacity((W + 20) * H);
        out.push_str("\x1B[H");
        for row in &buf {
            for &(l, h) in row {
                if l == 0 {
                    out.push(' ');
                } else {
                    let chars = " .·:░▒▓█";
                    let idx = (l as usize * (chars.len() - 1)) / 255;
                    let c = chars.chars().nth(idx).unwrap();
                    let col = if h > 180 { 196 } else if h > 100 { 208 } else if h > 50 { 220 } else { 15 };
                    out.push_str(&format!("\x1B[38;5;{}m{}\x1B[0m", col, c));
                }
            }
            out.push('\n');
        }
        print!("{}", out);
        io::stdout().flush().unwrap();
        sleep(Duration::from_millis(25));
    }
}
