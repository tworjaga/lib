use std::io::{self, Write};
use std::thread::sleep;
use std::time::Duration;

const W: usize = 80;
const H: usize = 24;

fn main() {
    print!("\x1B[2J\x1B[?25l");

    let mut grid = vec![vec![0u8; W]; H];
    let mut seed = 0x1337u64;

    let mut rand = || {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        (seed >> 33) as u32
    };

    // random seed
    for y in 0..H {
        for x in 0..W {
            if rand() % 5 == 0 {
                grid[y][x] = 1;
            }
        }
    }

    loop {
        let mut next = vec![vec![0u8; W]; H];

        for y in 0..H {
            for x in 0..W {
                let mut neighbors = 0;
                for dy in [-1isize, 0, 1] {
                    for dx in [-1isize, 0, 1] {
                        if dx == 0 && dy == 0 { continue; }
                        let ny = (y as isize + dy).rem_euclid(H as isize) as usize;
                        let nx = (x as isize + dx).rem_euclid(W as isize) as usize;
                        if grid[ny][nx] > 0 {
                            neighbors += 1;
                        }
                    }
                }

                if grid[y][x] > 0 {
                    if neighbors == 2 || neighbors == 3 {
                        next[y][x] = grid[y][x].saturating_add(1).min(255);
                    }
                } else if neighbors == 3 {
                    next[y][x] = 1;
                }
            }
        }

        grid = next;

        // render
        let mut out = String::with_capacity((W + 30) * H);
        out.push_str("\x1B[H");
        for row in &grid {
            for &age in row {
                if age == 0 {
                    out.push(' ');
                } else {
                    let c = if age == 1 { '░' } else if age < 10 { '▒' } else if age < 30 { '▓' } else { '█' };
                    let col = if age < 5 { 51 } else if age < 15 { 48 } else if age < 40 { 42 } else if age < 80 { 34 } else { 22 };
                    out.push_str(&format!("\x1B[38;5;{}m{}\x1B[0m", col, c));
                }
            }
            out.push('\n');
        }
        print!("{}", out);
        io::stdout().flush().unwrap();
        sleep(Duration::from_millis(80));
    }
}
