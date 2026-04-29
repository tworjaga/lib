use std::io::{self, Write};
use std::thread::sleep;
use std::time::Duration;

const W: usize = 80;
const H: usize = 24;
const GLYPHS: &str = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ0123456789";

fn main() {
    print!("\x1B[2J\x1B[?25l");
    let mut drops: Vec<(usize, usize, u8)> = Vec::new();
    let mut grid = vec![(' ', 0u8); W * H];

    loop {
        // spawn new drops
        if fast_rand() < 40 {
            let x = (fast_rand() as usize * W) >> 8;
            drops.push((x, 0, 180 + fast_rand() / 3));
        }

        // fade grid
        for cell in &mut grid {
            cell.1 = cell.1.saturating_sub(8);
        }

        // update drops
        let mut new_drops = Vec::new();
        for (x, y, brightness) in drops {
            let idx = y * W + x;
            if idx < grid.len() {
                let glyph = GLYPHS.chars().nth(
                    ((x + y + fast_rand() as usize) * 7) % GLYPHS.len()
                ).unwrap();
                grid[idx] = (glyph, brightness);
            }
            if y + 1 < H && brightness > 20 {
                new_drops.push((x, y + 1, brightness.saturating_sub(6)));
            }
        }
        drops = new_drops;

        // render
        let mut out = String::with_capacity((W + 20) * H);
        out.push_str("\x1B[H");
        for y in 0..H {
            for x in 0..W {
                let (ch, bri) = grid[y * W + x];
                if bri > 140 {
                    out.push_str("\x1B[1;32m"); // bright green head
                } else if bri > 60 {
                    out.push_str("\x1B[0;32m"); // green tail
                } else if bri > 0 {
                    out.push_str("\x1B[2;32m"); // dim green
                } else {
                    out.push_str("\x1B[0m");
                }
                out.push(ch);
            }
            out.push_str("\x1B[0m\n");
        }
        print!("{}", out);
        io::stdout().flush().unwrap();
        sleep(Duration::from_millis(40));
    }
}

static mut SEED: u
