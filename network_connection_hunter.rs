use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;

const PROC_NET_TCP: &str = "/proc/net/tcp";
const PROC_NET_TCP6: &str = "/proc/net/tcp6";
const PROC_DIR: &str = "/proc";

#[derive(Debug)]
struct Conn {
    local: String,
    remote: String,
    state: &'static str,
    inode: u64,
    uid: u32,
}

fn main() {
    println!("[*] hunting active connections...");
    println!("{:-<70}", "");

    let mut conns = Vec::new();
    conns.extend(parse_tcp(PROC_NET_TCP, false));
    conns.extend(parse_tcp(PROC_NET_TCP6, true));

    let inode_map = build_inode_map();

    for conn in &conns {
        let proc_info = inode_map.get(&conn.inode)
            .map(|(pid, name, exe)| format!("{}[{}] ({})", name, pid, exe))
            .unwrap_or_else(|| "unknown".to_string());

        let flag = assess_remote(&conn.remote, conn.state);

        println!(
            "{:>8} {:>25} -> {:>25}  {:>12}  {}",
            flag,
            conn.local,
            conn.remote,
            proc_info,
            conn.state
        );
    }

    println!("{:-<70}", "");
    println!("[*] total connections: {}", conns.len());
}

fn parse_tcp(path: &str, _ipv6: bool) -> Vec<Conn> {
    let mut result = Vec::new();
    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return result,
    };

    let reader = BufReader::new(file);
    for (idx, line) in reader.lines().flatten().enumerate() {
        if idx == 0 { continue; } // skip header

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 { continue; }

        let local = parse_addr(parts[1]);
        let remote = parse_addr(parts[2]);
        let state = state_name(parts[3]);
        let inode = parts[9].parse().unwrap_or(0);
        let uid = parts[7].parse().unwrap_or(0);

        result.push(Conn { local, remote, state, inode, uid });
    }

    result
}

fn parse_addr(hex: &str) -> String {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 { return hex.to_string(); }

    let ip = u32::from_str_radix(parts[0], 16).unwrap_or(0);
    let port = u16::from_str_radix(parts[1], 16).unwrap_or(0);

    let addr = Ipv4Addr::new(
        (ip & 0xFF) as u8,
        ((ip >> 8) & 0xFF) as u8,
        ((ip >> 16) & 0xFF) as u8,
        ((ip >> 24) & 0xFF) as u8,
    );

    format!("{}:{}", addr, port)
}

fn state_name(hex: &str) -> &'static str {
    match hex {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    }
}

fn build_inode_map() -> HashMap<u64, (u32, String, String)> {
    let mut map = HashMap::new();

    let entries = match fs::read_dir(PROC_DIR) {
        Ok(e) => e,
        Err(_) => return map,
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let pid_str = match name.to_str() {
            Some(s) => s,
            None => continue,
        };

        let pid: u32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let comm = read_comm(pid);
        let exe = read_exe(pid);
        let fds = format!("{}/{}/fd", PROC_DIR, pid);

        let fd_entries = match fs::read_dir(&fds) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for fd in fd_entries.flatten() {
            let link = match fs::read_link(fd.path()) {
                Ok(p) => p,
                Err(_) => continue,
            };

            let link_str = link.to_string_lossy();
            if let Some(inode_str) = link_str.strip_prefix("socket:[") {
                if let Some(num) = inode_str.strip_suffix(']') {
                    if let Ok(inode) = num.parse::<u64>() {
                        map.insert(inode, (pid, comm.clone(), exe.clone()));
                    }
                }
            }
        }
    }

    map
}

fn read_comm(pid: u32) -> String {
    let path = format!("{}/{}/comm", PROC_DIR, pid);
    fs::read_to_string(path)
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn read_exe(pid: u32) -> String {
    let path = format!("{}/{}/exe", PROC_DIR, pid);
    fs::read_link(path)
        .unwrap_or_default()
        .to_string_lossy()
        .to_string()
}

fn assess_remote(remote: &str, state: &str) -> String {
    if state != "ESTABLISHED" && state != "SYN_SENT" {
        return "\x1B[2m[--]\x1B[0m".to_string();
    }

    if remote.starts_with("0.0.0.0") || remote.starts_with("127.") {
        return "\x1B[2m[lo]\x1B[0m".to_string();
    }

    let parts: Vec<&str> = remote.split(':').collect();
    if parts.len() != 2 { return "\x1B[33m[??]\x1B[0m".to_string(); }

    let port: u16 = parts[1].parse().unwrap_or(0);

    // known C2 / suspicious ports
    let suspicious = match port {
        4444 => "metasploit default",
        5555 => "adb / potential backdoor",
        6666 | 6667 | 6668 | 6669 => "IRC / botnet C2",
        31337 => "classic backdoor",
        12345 | 12346 => "netbus / common backdoor",
        22 => "SSH outbound",
        23 => "TELNET plaintext",
        3389 => "RDP outbound",
        5900 => "VNC outbound",
        _ => "",
    };

    if !suspicious.is_empty() {
        format!("\x1B[1;31m[!]\x1B[0m")
    } else if port > 49152 {
        format!("\x1B[33m[ep]\x1B[0m")
    } else {
        format!("\x1B[32m[ok]\x1B[0m")
    }
}
