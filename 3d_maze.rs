use std::io::{self, Write};
use std::thread::sleep;
use std::time::Duration;

const W: usize = 80;
const H: usize = 24;
const MAP: &str = "#########\
                   #.......#\
                   #.##.##.#\
                   #.#...#.#\
                   #.#.#.#.#\
                   #.....#.#\
                   #.###...#\
                   #.......#\
                   #########";

fn main() {
    let map: Vec<bool> = MAP.bytes().map(|b| b == b'#').collect();
    let mw = 9usize;
    let mut px = 1.5;
    let mut py = 1.5;
    let mut pa = 0.0;

    print!("\x1B[2J\x1B[?25l");

    loop {
        // input (non-blocking via /dev/tty would need libc, so we auto-rotate)
        pa += 0.03;

        let mut out = String::with_capacity((W + 30) * H);
        out.push_str("\x1B[H");

        // ceiling
        for _ in 0..H / 2 {
            out.push_str("\x1B[48;5;232m");
            out.extend(std::iter::repeat(' ').take(W));
            out.push_str("\x1B[0m\n");
        }

        // walls
        for x in 0..W {
            let ra = pa + (x as f64 / W as f64 - 0.5) * 1.2;
            let (rdx, rdy) = (ra.cos(), ra.sin());

            let mut dist = 0.0;
            let mut hit = false;
            while dist < 16.0 && !hit {
                dist += 0.02;
                let mx = (px + rdx * dist) as usize;
                let my = (py + rdy * dist) as usize;
                if my * mw + mx < map.len() && map[my * mw + mx] {
                    hit = true;
                }
            }

            let wall_h = (H as f64 / (dist + 0.1)) as usize;
            let wall_h = wall_h.min(H - 2);
            let shade = (255.0 / (1.0 + dist * dist * 0.1)) as u8;

            for y in 0..H / 2 {
                let row = H / 2 + y;
                if y < wall_h / 2 {
                    let col = if shade > 180 { 15 } else if shade > 100 { 7 } else { 8 };
                    out.push_str(&format!("\x1B[48;5;{}m \x1B[0m", col));
                } else {
                    out.push_str("\x1B[48;5;234m \x1B[0m");
                }
            }
            out.push('\n');
        }

        print!("{}", out);
        io::stdout().flush().unwrap();
        sleep(Duration::from_millis(16));
    }
}
