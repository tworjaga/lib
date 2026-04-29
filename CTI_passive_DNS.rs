use std::net::{TcpStream, ToSocketAddrs};
use std::io::{Read, Write};
use std::time::Duration;

const RESOLVERS: &[&str] = &[
    "8.8.8.8:53",
    "1.1.1.1:53",
    "9.9.9.9:53",
    "208.67.222.222:53",
];

const DNS_QUERY_TEMPLATE: &[u8] = &[
    0x00, 0x35, // tx id
    0x01, 0x00, // flags: standard query
    0x00, 0x01, // questions: 1
    0x00, 0x00, // answer RRs
    0x00, 0x00, // authority RRs
    0x00, 0x00, // additional RRs
];

fn main() {
    let target = std::env::args().nth(1)
        .unwrap_or_else(|| {
            eprintln!("usage: dns_enrich <domain>");
            std::process::exit(1);
        });

    println!("[*] enriching: {}", target);
    println!("{:-<60}", "");

    let encoded = encode_name(&target);
    let mut results = Vec::new();

    for resolver in RESOLVERS {
        match query_resolver(resolver, &encoded) {
            Ok(ips) => {
                println!("[+] {:>21} -> {} record(s)", resolver, ips.len());
                for ip in &ips {
                    let rep = reputation_check(ip);
                    println!("    {} {}", ip, rep);
                }
                results.extend(ips);
            }
            Err(e) => println!("[-] {:>21} -> {}", resolver, e),
        }
    }

    // anomaly detection
    println!("{:-<60}", "");
    let unique: std::collections::HashSet<_> = results.iter().cloned().collect();
    if unique.len() > 1 {
        println!("[!] ANOMALY: inconsistent A records across resolvers");
        println!("    distinct IPs: {}", unique.len());
    }

    if let Some(ip) = results.first() {
        if ip.starts_with("10.") || ip.starts_with("192.168.") || ip.starts_with("127.") {
            println!("[!] ANOMALY: RFC1918/loopback response for public domain");
        }
    }
}

fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for part in name.split('.') {
        out.push(part.len() as u8);
        out.extend_from_slice(part.as_bytes());
    }
    out.push(0x00);
    // A record query
    out.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    out
}

fn query_resolver(resolver: &str, query: &[u8]) -> Result<Vec<String>, String> {
    let mut stream = TcpStream::connect_timeout(
        &resolver.to_socket_addrs().unwrap().next().unwrap(),
        Duration::from_secs(3)
    ).map_err(|e| e.to_string())?;

    let len = (query.len() as u16).to_be_bytes();
    stream.write_all(&len).map_err(|e| e.to_string())?;
    stream.write_all(query).map_err(|e| e.to_string())?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).map_err(|e| e.to_string())?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).map_err(|e| e.to_string())?;

    parse_a_records(&resp)
}

fn parse_a_records(resp: &[u8]) -> Result<Vec<String>, String> {
    if resp.len() < 12 { return Err("short response".into()); }

    let qdcount = u16::from_be_bytes([resp[4], resp[5]]);
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);

    let mut offset = 12;

    // skip questions
    for _ in 0..qdcount {
        while offset < resp.len() && resp[offset] != 0 {
            if resp[offset] & 0xC0 == 0xC0 {
                offset += 2;
                break;
            }
            offset += 1 + resp[offset] as usize;
        }
        if offset < resp.len() && resp[offset] == 0 { offset += 1; }
        offset += 4; // QTYPE + QCLASS
    }

    let mut ips = Vec::new();
    for _ in 0..ancount {
        // skip name (compression possible)
        while offset < resp.len() {
            if resp[offset] & 0xC0 == 0xC0 {
                offset += 2;
                break;
            }
            if resp[offset] == 0 {
                offset += 1;
                break;
            }
            offset += 1 + resp[offset] as usize;
        }

        if offset + 10 > resp.len() { break; }
        let rtype = u16::from_be_bytes([resp[offset], resp[offset + 1]]);
        let rdlength = u16::from_be_bytes([resp[offset + 8], resp[offset + 9]]);
        offset += 10;

        if rtype == 1 && rdlength == 4 { // A record
            let ip = format!("{}.{}.{}.{}",
                resp[offset], resp[offset + 1],
                resp[offset + 2], resp[offset + 3]);
            ips.push(ip);
        }
        offset += rdlength as usize;
    }

    Ok(ips)
}

fn reputation_check(ip: &str) -> &'static str {
    // simplistic checks — hook into real threat intel APIs in production
    if ip.starts_with("0.") || ip.starts_with("255.") {
        "\x1B[1;31m[SUSPICIOUS: bogon]\x1B[0m"
    } else {
        "\x1B[2m[no local intel]\x1B[0m"
    }
}
