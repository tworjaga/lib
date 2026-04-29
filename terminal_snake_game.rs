use std::io::{self, Write, Read};
use std::thread::sleep;
use std::time::Duration;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

const W: usize = 40;
const H: usize = 20;

#[derive(Clone, Copy, PartialEq)]
enum Dir { Up, Down, Left, Right }

fn main() {
    print!("\x1B[2J\x1B[?25l");

    let running = Arc::new(AtomicBool::new(true));
    let dir = Arc::new(Mutex::new(Dir::Right));
    let r = running.clone();
    let d = dir.clone();

    // raw input thread
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut buf = [0u8; 1];
        while r.load(Ordering::Relaxed) {
            if stdin.lock().read_exact(&mut buf).is_ok() {
                let mut lock = d.lock().unwrap();
                match buf[0] {
                    b'w' | b'W' => if *lock != Dir::Down { *lock = Dir::Up; },
                    b's' | b'S' => if *lock != Dir::Up { *lock = Dir::Down; },
                    b'a' | b'A' => if *lock != Dir::Right { *lock = Dir::Left; },
                    b'd' | b'D' => if *lock != Dir::Left { *lock = Dir::Right; },
                    b'q' => r.store(false, Ordering::Relaxed),
                    _ => {}
                }
            }
        }
    });

    let mut snake = vec![(W / 2, H / 2), (W / 2 - 1, H / 2), (W / 2 - 2, H / 2)];
    let mut food = (W * 3 / 4, H / 2);
    let mut seed = 0xCAFEu64;

    let mut rand = || {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        (seed >> 33) as u32
    };

    while running.load(Ordering::Relaxed) {
        let current_dir = *dir.lock().unwrap();

        let head = snake[0];
        let new_head = match current_dir {
            Dir::Up => (head.0, head.1.wrapping_sub(1)),
            Dir::Down => (head.0, head.1 + 1),
            Dir::Left => (head.0.wrapping_sub(1), head.1),
            Dir::Right => (head.0 + 1, head.1),
        };

        // wall collision
        if new_head.0 >=
