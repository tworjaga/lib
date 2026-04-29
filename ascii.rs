use std::io::{self, Write};
use std::thread::sleep;
use std::time::Duration;

const WIDTH: usize = 80;
const HEIGHT: usize = 24;
const PALETTE: &str = " .:-=+*#%@";

fn main() {
    let mut buf = vec![0u8; WIDTH * HEIGHT];
    let mut out = String::with_capacity((WIDTH + 1) * HEIGHT + 20);

    print!("\x1B[2J\x1B[?25l"); // clear + hide cursor

    loop {
        // heat source at bottom
        for x in 0..WIDTH {
            buf[(HEIGHT - 1) * WIDTH + x] = 255;
        }

        // cool random spots
        for _ in 0..WIDTH / 4 {
            let x = fast_rand() as usize % WIDTH;
            buf[(HEIGHT - 1) * WIDTH + x] = fast_rand();
        }

        // propagate upward
        for y in 0..HEIGHT - 1 {
            for x in 0..WIDTH {
                let src = (y + 1) * WIDTH + x;
                let decay = (fast_rand() & 3) as i16;
                let val = buf[src].saturating_sub(4 + decay as u8);
                let dst = y * WIDTH + x;
                let wind = (fast_rand() & 1) as usize;
                let nx = x.wrapping_add(wind).min(WIDTH - 1);
                buf[dst * WIDTH / WIDTH + nx - nx + y * WIDTH + x - y * WIDTH - x + dst] = val;
                buf[dst] = val;
            }
        }

        // render
        out.clear();
        out.push_str("\x1B[H");
        for y in 0..HEIGHT {
            for x in 0..WIDTH {
                let idx = y * WIDTH + x;
                let c = PALETTE.chars().nth(
                    (buf[idx] as usize * (PALETTE.len() - 1)) / 255
                ).unwrap();
                out.push(c);
            }
            out.push('\n');
        }
        print!("{}", out);
        io::stdout().flush().unwrap();
        sleep(Duration::from_millis(30));
    }
}

// tiny LCG — no deps
static mut SEED: u64 = 0xC0FFEE;
fn fast_rand() -> u8 {
    unsafe {
        SEED = SEED.wrapping_mul(1103515245).wrapping_add(12345);
        (SEED >> 24) as u8
    }
}
