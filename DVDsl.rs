use std::io::{self, Write};
use std::thread::sleep;
use std::time::Duration;

const W: usize = 80;
const H: usize = 24;

fn main() {
    print!("\x1B[2J\x1B[?25l");
    let mut grid = vec![vec![(0u8, 0u8, 0u8); W]; H];

    let mut x = 5.0;
    let mut y = 3.0;
    let mut vx = 0.7;
    let mut vy = 0.4;
    let mut hue = 0u16;

    loop {
        // fade trails
        for row in &mut grid {
            for cell in row.iter_mut() {
                cell.0 = cell.0.saturating_sub(3);
                cell.1 = cell.1.saturating_sub(3);
                cell.2 = cell.2.saturating_sub(3);
            }
        }

        // update position
        x += vx;
        y += vy;

        // bounce
        if x <= 0.0 || x >= W as f64 - 6.0 {
            vx = -vx;
            hue = (hue + 60) % 360;
        }
        if y <= 0.0 || y >= H as f64 - 3.0 {
            vy = -vy;
            hue = (hue + 60) % 360;
        }

        // draw logo
        let (r, g, b) = hsv(hue);
        for dy in 0..3usize {
            for dx in 0..6usize {
                let gy = (y as usize + dy).min(H - 1);
                let gx = (x as usize + dx).min(W - 1);
                grid[gy][gx] = (r, g, b);
            }
        }

        // render
        let mut out = String::with_capacity((W + 20) * H);
        out.push_str("\x1B[H");
        for row in &grid {
            for &(r, g, b) in row {
                if r | g | b == 0 {
                    out.push(' ');
                } else {
                    out.push_str(&format!("\x1B[38;2;{};{};{}m█\x1B[0m", r, g, b));
                }
            }
            out.push('\n');
        }
        print!("{}", out);
        io::stdout().flush().unwrap();
        sleep(Duration::from_millis(30));
    }
}

fn hsv(h: u16) -> (u8, u8, u8) {
    let h = h as f64;
    let c = 255.0;
    let x = c * (1.0 - ((h / 60.0) % 2.0 - 1.0).abs());
    let m = 0.0;
    let (r, g, b) = match (h / 60.0) as u8 {
        0 => (c, x, 0.0),
        1 => (x, c, 0.0),
        2 => (0.0, c, x),
        3 => (0.0, x, c),
        4 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    ((r + m) as u8, (g + m) as u8, (b + m) as u8)
}
