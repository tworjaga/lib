// ═══════════════════════════════════════════════════════════════
//  AEGIS-CTI  v2.0  —  Cyber Threat Intelligence Terminal Suite
//  Windows-focused, single-binary, zero-config for basic ops
// ═══════════════════════════════════════════════════════════════

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Read, Write, BufRead};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

// ── colors ───────────────────────────────────────────────────
mod c {
    pub const G: &str = "\x1B[92m";
    pub const Y: &str = "\x1B[93m";
    pub const R: &str = "\x1B[91m";
    pub const CY: &str = "\x1B[96m";
    pub const W: &str = "\x1B[97m";
    pub const DIM: &str = "\x1B[2m";
    pub const M: &str = "\x1B[95m";
    pub const RST: &str = "\x1B[0m";
}

fn clr(c: &str, t: &str) -> String { format!("{}{}{}", c, t, c::RST) }
fn ok(msg: &str) { println!("  {} {}", clr(c::G, "[+]"), msg); }
fn info(msg: &str) { println!("  {} {}", clr(c::CY, "[*]"), msg); }
fn warn(msg: &str) { println!("  {} {}", clr(c::Y, "[!]"), msg); }
fn err(msg: &str) { println!("  {} {}", clr(c::R, "[-]"), msg); }
fn dim(msg: &str) { println!("  {}", clr(c::DIM, msg)); }
fn hit(msg: &str) { println!("  {} {}", clr(c::M, "[HIT]"), msg); }
fn crit(msg: &str) { println!("  {} {}", clr(c::R, "[CRIT]"), msg); }

fn sep(label: &str) {
    let w = 64;
    if label.is_empty() {
        println!("  {}", clr(c::DIM, &"─".repeat(w)));
    } else {
        let pad = (w.saturating_sub(label.len()).saturating_sub(2)) / 2;
        println!("  {}", clr(c::G, &format!("{} {} {}", "─".repeat(pad), label, "─".repeat(pad))));
    }
}

// ── input / validation ───────────────────────────────────────
fn input(prompt: &str) -> String {
    print!("\n  {} {}: ", clr(c::G, "▶"), prompt);
    let _ = io::stdout().flush();
    let mut s = String::new();
    match io::stdin().read_line(&mut s) {
        Ok(0) => String::new(),
        Ok(_) => s.trim().to_string(),
        Err(_) => String::new(),
    }
}

fn validate_target(s: &str) -> Result<String, String> {
    let s = s.trim();
    if s.is_empty() { return Err("Empty target".into()); }
    if s.len() > 512 { return Err("Target too long".into()); }
    
    let body = s.strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s);
    
    let allowed = body.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '/' | '_' | '*' | '?' | '=' | '&' | '%' | '@')
    });
    if !allowed {
        return Err(format!("Target '{}' contains disallowed characters", s));
    }
    Ok(s.to_string())
}

fn resolve(target: &str) -> String {
    if target.parse::<IpAddr>().is_ok() { return target.to_string(); }
    match format!("{}:0", target).to_socket_addrs() {
        Ok(mut addrs) => addrs.next().map(|sa| sa.ip().to_string()).unwrap_or_else(|| target.to_string()),
        Err(_) => target.to_string(),
    }
}

// ── report engine ────────────────────────────────────────────
const REPORT_DIR: &str = "cti_reports";

struct Report {
    module: String,
    target: String,
    started: Instant,
    started_at: String,
    buf: Vec<u8>,
}

impl Report {
    fn new(module: &str, target: &str) -> Result<Self, io::Error> {
        fs::create_dir_all(REPORT_DIR)?;
        Ok(Self {
            module: module.to_string(),
            target: target.to_string(),
            started: Instant::now(),
            started_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            buf: Vec::new(),
        })
    }
    fn log(&mut self, line: &str) {
        self.buf.extend_from_slice(strip_ansi(line).as_bytes());
        self.buf.push(b'\n');
    }
    fn save(mut self) -> Result<(), io::Error> {
        let elapsed = self.started.elapsed().as_secs_f64();
        let safe = self.target.replace(|c: char| !c.is_alphanumeric() && c != '.' && c != '-', "_");
        let ts = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let fname = format!("{}/{}_{}_{}.txt", REPORT_DIR, self.module, safe, ts);
        
        let header = format!(
            "{}\n  AEGIS-CTI REPORT\n  Module  : {}\n  Target  : {}\n  Started : {}\n  Elapsed : {:.1}s\n{}\n\n",
            "=".repeat(60), self.module.to_uppercase(), self.target, self.started_at, elapsed, "=".repeat(60)
        );
        
        let mut file = fs::File::create(&fname)?;
        file.write_all(header.as_bytes())?;
        file.write_all(&self.buf)?;
        println!("\n  {} Report saved → {}", clr(c::G, "[✔]"), fname);
        Ok(())
    }
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_esc = false;
    let mut in_csi = false;
    for ch in s.chars() {
        if in_esc {
            if ch == '[' { in_csi = true; in_esc = false; }
            else { in_esc = false; }
        } else if in_csi {
            let b = ch as u32;
            if (0x40..=0x7E).contains(&b) { in_csi = false; }
        } else if ch == '\x1B' {
            in_esc = true;
        } else {
            out.push(ch);
        }
    }
    out
}

// ── HTTP helper ──────────────────────────────────────────────
fn http_get(url: &str, timeout_secs: u64) -> Result<String, ureq::Error> {
    ureq::get(url)
        .set("User-Agent", "AEGIS-CTI/2.0")
        .timeout(Duration::from_secs(timeout_secs))
        .call()?
        .into_string()
        .map_err(|e| ureq::Error::Io(e))
}

// ── banner & menu ────────────────────────────────────────────
fn banner() {
    println!("{}", clr(c::G, r#"
    ___    ________  _________  ____  ___   _____ _______ ______
   /   |  / ____/  |/  /  _/  |/  / |/  /  / ___// ____(_) __/
  / /| | / __/ / /|_/ // // /|_/ /|_/ /   \__ \/ /   / / /_  
 / ___ |/ /___/ /  / // // /  / //_/ /   ___/ / /___/ / __/  
/_/  |_/_____/_/  /_/___/_/  /_//___/   /____/\____/_/_/     
"#));
    println!("  {}  |  {}", clr(c::DIM, "CYBER THREAT INTELLIGENCE SUITE"), clr(c::DIM, "v2.0"));
    println!("  {} ./{}/", clr(c::DIM, "Reports →"), REPORT_DIR);
    println!();
}

fn menu() {
    println!("{}", clr(c::G, "\n  ┌─── AEGIS-CTI MODULES ──────────────────────────────────────┐"));
    let mods = [
        ("1",  "Hash Analyzer",         "VT + MalwareBazaar + Abuse.ch lookup"),
        ("2",  "IP Reputation",         "AbuseIPDB + GreyNoise + Shodan + geolocation"),
        ("3",  "Domain Intel",          "WHOIS + DNS + subdomains + SSL certs"),
        ("4",  "URL Scanner",           "HTTP headers + security audit + redirect chain"),
        ("5",  "File Analyzer",         "PE headers + entropy + strings + YARA"),
        ("6",  "IOC Extractor",         "Extract IOCs from text/files/paste"),
        ("7",  "MITRE ATT&CK Mapper",   "Map TTPs to techniques & sub-techniques"),
        ("8",  "CVE Lookup",            "NVD + Vulners + exploit availability"),
        ("9",  "Threat Actor DB",       "APT/crime group TTPs and IOCs"),
        ("10", "YARA Scanner",          "Scan files with custom/community rules"),
        ("11", "Windows EVTX Parser",   "Parse .evtx with Sigma correlation"),
        ("12", "Prefetch Analyzer",     "Windows Prefetch execution timeline"),
        ("13", "Registry Hive Parser",  "ShimCache, AmCache, UserAssist"),
        ("14", "Memory String Search",  "String extraction from raw dumps"),
        ("15", "CyberChef Pipe",        "Encode/decode/hash/transform data"),
        ("16", "Timeline Generator",    "Build timeline from mixed evidence"),
        ("17", "Report Generator",      "Export Markdown/HTML/JSON reports"),
        ("18", "Phishing Detector",     "Homograph + typosquat detection"),
        ("19", "C2 Config Extractor",   "Parse known malware C2 configs"),
        ("20", "Dark Web Monitor",      "Query paste sites for leaks/IOCs"),
        ("21", "Batch IOC Enrich",      "Process IOC lists from file"),
        ("22", "Correlation Engine",    "Cross-ref IOCs for shared infra"),
        ("23", "Sandbox Submit",        "Submit to Hybrid Analysis / Any.Run"),
        ("24", "Google Dork Gen",       "Recon dork queries"),
        ("25", "Full CTI Recon",        "Run all modules on target"),
        ("26", "View Saved Reports",    "List & read saved scans"),
        ("0",  "Exit",                  ""),
    ];
    for (n, name, desc) in &mods {
        println!("  │  {} {} {}",
            clr(c::Y, &format!("{:>2}", n)),
            clr(c::W, &format!("{:<22}", name)),
            clr(c::DIM, desc)
        );
    }
    println!("{}", clr(c::G, "  └────────────────────────────────────────────────────────┘"));
}

// ═══════════════════════════════════════════════════════════════
//  MODULE 1: HASH ANALYZER (Multi-engine IOC lookup)
// ═══════════════════════════════════════════════════════════════
fn module_hash(target: &str) {
    let mut r = match Report::new("hash", target) { Ok(r) => r, Err(e) => { err(&format!("Report error: {}", e)); return; } };
    sep("HASH ANALYZER");
    info(&format!("Querying: {}", clr(c::W, target)));
    
    let hash = target.to_lowercase().trim().to_string();
    let hash_type = match hash.len() {
        32 => "MD5",
        40 => "SHA1",
        64 => "SHA256",
        _ => { warn("Unknown hash length. Expected MD5(32), SHA1(40), or SHA256(64)"); return; }
    };
    ok(&format!("Detected hash type: {}", hash_type));
    r.log(&format!("Hash: {} ({})", hash, hash_type));

    // MalwareBazaar lookup
    info("Querying MalwareBazaar...");
    let mb_url = format!("https://mb-api.abuse.ch/api/v1/");
    let mb_body = format!("query=get_info&hash={}", hash);
    match ureq::post(&mb_url)
        .set("User-Agent", "AEGIS-CTI/2.0")
        .set("Content-Type", "application/x-www-form-urlencoded")
        .timeout(Duration::from_secs(10))
        .send_string(&mb_body) {
        Ok(resp) => {
            if let Ok(text) = resp.into_string() {
                if text.contains("\"query_status\":\"ok\"") {
                    hit("MalwareBazaar: Known malware sample found!");
                    r.log("MalwareBazaar: POSITIVE");
                    // Extract key fields
                    for line in text.lines() {
                        if line.contains("\"file_name\"") || line.contains("\"file_type\"") 
                           || line.contains("\"signature\"") || line.contains("\"first_seen\"") {
                            dim(&format!("    {}", line.trim().trim_end_matches(',')));
                            r.log(line);
                        }
                    }
                } else {
                    ok("MalwareBazaar: Not found in database");
                    r.log("MalwareBazaar: NEGATIVE");
                }
            }
        }
        Err(e) => warn(&format!("MalwareBazaar error: {}", e)),
    }

    // VirusTotal (requires API key - show what would be queried)
    info("VirusTotal: Configure API key in config for full lookup");
    info(&format!("  VT lookup URL: https://www.virustotal.com/gui/file/{}", hash));
    r.log(&format!("VirusTotal: https://www.virustotal.com/gui/file/{}", hash));

    // Abuse.ch URLhaus for URLs associated with hash
    info("Checking Abuse.ch URLhaus...");
    let uh_url = format!("https://urlhaus-api.abuse.ch/v1/payload/{}", hash);
    match http_get(&uh_url, 8) {
        Ok(text) => {
            if text.contains("\"query_status\":\"ok\"") {
                hit("URLhaus: Associated URLs found!");
                r.log("URLhaus: POSITIVE");
            } else {
                ok("URLhaus: No associated URLs");
                r.log("URLhaus: NEGATIVE");
            }
        }
        Err(_) => dim("  URLhaus: No data"),
    }

    if let Err(e) = r.save() { err(&format!("Save failed: {}", e)); }
}

// ═══════════════════════════════════════════════════════════════
//  MODULE 2: IP REPUTATION (AbuseIPDB + Geo + ASN)
// ═══════════════════════════════════════════════════════════════
fn module_ip_reputation(target: &str) {
    let mut r = match Report::new("ip_reputation", target) { Ok(r) => r, Err(e) => { err(&format!("Report error: {}", e)); return; } };
    sep("IP REPUTATION & GEOLOCATION");
    
    let ip = resolve(target);
    if ip != target { info(&format!("Resolved {} → {}", target, clr(c::W, &ip))); }
    
    // Validate IP
    let ip_addr = match ip.parse::<IpAddr>() {
        Ok(a) => a,
        Err(_) => { err("Invalid IP address"); return; }
    };

    // Geolocation via ipapi.co
    info("Querying geolocation...");
    let geo_url = format!("https://ipapi.co/{}/json/", ip);
    match http_get(&geo_url, 8) {
        Ok(text) => {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                if json.get("error").is_none() {
                    let fields = [
                        ("IP", json.get("ip").and_then(|v| v.as_str())),
                        ("City", json.get("city").and_then(|v| v.as_str())),
                        ("Region", json.get("region").and_then(|v| v.as_str())),
                        ("Country", json.get("country_name").and_then(|v| v.as_str())),
                        ("ISP/Org", json.get("org").and_then(|v| v.as_str())),
                        ("ASN", json.get("asn").and_then(|v| v.as_str())),
                        ("Latitude", json.get("latitude").and_then(|v| v.as_f64()).map(|f| f.to_string())),
                        ("Longitude", json.get("longitude").and_then(|v| v.as_f64()).map(|f| f.to_string())),
                    ];
                    for (k, v) in &fields {
                        if let Some(val) = v {
                            ok(&format!("{}: {}", format!("{:<12}", k), clr(c::G, val)));
                            r.log(&format!("{}: {}", k, val));
                        }
                    }
                }
            }
        }
        Err(e) => warn(&format!("Geo lookup failed: {}", e)),
    }

    // AbuseIPDB check (requires API key - show manual URL)
    info("AbuseIPDB: Configure API key for automated check");
    info(&format!("  Manual check: https://www.abuseipdb.com/check/{}", ip));
    r.log(&format!("AbuseIPDB: https://www.abuseipdb.com/check/{}", ip));

    // GreyNoise (requires API key)
    info("GreyNoise: Configure API key for internet noise classification");
    info(&format!("  Check: https://viz.greynoise.io/ip/{}", ip));

    // Shodan (requires API key)
    info("Shodan: Configure API key for exposed services");
    info(&format!("  Check: https://www.shodan.io/host/{}", ip));

    // Reverse DNS
    info("Performing reverse DNS lookup...");
    let rev_cmd = if cfg!(target_os = "windows") {
        run_cmd("powershell", &["-Command", &format!("[System.Net.Dns]::GetHostEntry('{}').HostName", ip)])
    } else {
        run_cmd("dig", &["+short", "-x", &ip])
    };
    match rev_cmd {
        Some(hostname) if !hostname.trim().is_empty() => {
            ok(&format!("PTR record: {}", hostname.trim()));
            r.log(&format!("PTR: {}", hostname.trim()));
        }
        _ => dim("  No PTR record found"),
    }

    // Port scan top 20
    info("Quick port scan (top 20)...");
    let top_ports = [21,22,23,25,53,80,110,143,443,445,3306,3389,5432,5900,6379,8080,8443,9200,27017,11211];
    let (tx, rx) = mpsc::channel::<(u16, String)>();
    let mut handles = vec![];
    
    for &port in &top_ports {
        let ip = ip.clone();
        let tx = tx.clone();
        handles.push(thread::spawn(move || {
            let addr = SocketAddr::new(ip_addr, port);
            if TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_ok() {
                // Banner grab
                let banner = match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
                    Ok(mut stream) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut buf = [0u8; 256];
                        match stream.read(&mut buf) {
                            Ok(n) => String::from_utf8_lossy(&buf[..n]).lines().next().unwrap_or("").to_string(),
                            Err(_) => String::new(),
                        }
                    }
                    Err(_) => String::new(),
                };
                let _ = tx.send((port, banner));
            }
        }));
    }
    drop(tx);
    for h in handles { let _ = h.join(); }
    
    let mut open_ports: Vec<_> = rx.into_iter().collect();
    open_ports.sort_by_key(|p| p.0);
    
    if !open_ports.is_empty() {
        hit(&format!("{} open ports detected:", open_ports.len()));
        for (port, banner) in &open_ports {
            let svc = service_name(*port);
            println!("  {} {:<6} {:<16} {}", clr(c::G, "[OPEN]"), port, svc, clr(c::DIM, &banner[..60.min(banner.len())]));
            r.log(&format!("OPEN {} ({}) - {}", port, svc, banner));
        }
    } else {
        ok("No open ports on top 20");
    }

    if let Err(e) = r.save() { err(&format!("Save failed: {}", e)); }
}

fn service_name(port: u16) -> &'static str {
    match port {
        21 => "FTP", 22 => "SSH", 23 => "Telnet", 25 => "SMTP", 53 => "DNS",
        80 => "HTTP", 110 => "POP3", 143 => "IMAP", 443 => "HTTPS", 445 => "SMB",
        3306 => "MySQL", 3389 => "RDP", 5432 => "PostgreSQL", 5900 => "VNC",
        6379 => "Redis", 8080 => "HTTP-Alt", 8443 => "HTTPS-Alt", 9200 => "Elastic",
        27017 => "MongoDB", 11211 => "Memcached", _ => "Unknown",
    }
}

// ═══════════════════════════════════════════════════════════════
//  MODULE 3: DOMAIN INTELLIGENCE (WHOIS + DNS + Subdomains + SSL)
// ═══════════════════════════════════════════════════════════════
fn module_domain_intel(target: &str) {
    let mut r = match Report::new("domain_intel", target) { Ok(r) => r, Err(e) => { err(&format!("Report error: {}", e)); return; } };
    sep("DOMAIN INTELLIGENCE");
    info(&format!("Target: {}", clr(c::W, target)));
    
    let domain = target.replace("https://", "").replace("http://", "").split('/').next().unwrap_or(target).to_string();

    // WHOIS / RDAP
    info("Querying WHOIS/RDAP...");
    let rdap_url = format!("https://rdap.org/domain/{}", domain);
    match http_get(&rdap_url, 10) {
        Ok(text) => {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                if let Some(events) = json.get("events").and_then(|e| e.as_array()) {
                    for ev in events {
                        if let (Some(action), Some(date)) = (
                            ev.get("eventAction").and_then(|v| v.as_str()),
                            ev.get("eventDate").and_then(|v| v.as_str())
                        ) {
                            ok(&format!("{}: {}", format!("{:<20}", action), clr(c::G, date)));
                            r.log(&format!("{}: {}", action, date));
                        }
                    }
                }
                if let Some(entities) = json.get("entities").and_then(|e| e.as_array()) {
                    for ent in entities {
                        if let Some(roles) = ent.get("roles").and_then(|r| r.as_array()) {
                            let role_str = roles.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", ");
                            if let Some(handle) = ent.get("handle").and_then(|v| v.as_str()) {
                                ok(&format!("{}: {}", format!("{:<20}", &role_str), handle));
                                r.log(&format!("{}: {}", role_str, handle));
                            }
                        }
                    }
                }
            }
        }
        Err(e) => warn(&format!("RDAP failed: {}", e)),
    }

    // DNS enumeration
    sep("DNS RECORDS");
    let record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SPF", "DKIM"];
    for rtype in &record_types {
        let output = if cfg!(target_os = "windows") {
            run_cmd("nslookup", &["-type=", rtype, &domain])
        } else {
            run_cmd("dig", &["+short", "+time=2", rtype, &domain])
        };
        match output {
            Some(text) => {
                let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty() && !l.contains("Server:") && !l.contains("Address:")).collect();
                if !lines.is_empty() {
                    for line in lines {
                        ok(&format!("{} {}", format!("{:<8}", rtype), clr(c::G, line.trim())));
                        r.log(&format!("{} {}", rtype, line.trim()));
                    }
                }
            }
            None => dim(&format!("  {} no response", rtype)),
        }
    }

    // Subdomain enumeration (builtin wordlist)
    sep("SUBDOMAIN ENUMERATION");
    let sub_wordlist = [
        "www", "mail", "ftp", "api", "dev", "staging", "admin", "vpn", "blog", "shop",
        "portal", "app", "cdn", "static", "docs", "support", "login", "auth", "test",
        "beta", "secure", "git", "jenkins", "jira", "gitlab", "smtp", "webmail",
        "ns1", "ns2", "cpanel", "wp", "forum", "wiki", "store", "cloud",
        "dashboard", "monitor", "status", "health", "intranet", "backup",
        "db", "mysql", "redis", "elastic", "kibana", "grafana", "k8s", "docker",
        "build", "ci", "qa", "uat", "prod", "demo", "proxy", "api-v1", "api-v2",
        "graphql", "websocket", "ws", "cdn1", "cdn2", "assets", "media",
    ];
    
    let (tx, rx) = mpsc::channel::<(String, Vec<String>)>();
    let mut handles = vec![];
    
    for word in &sub_wordlist {
        let full = format!("{}.{}", word, domain);
        let tx = tx.clone();
        handles.push(thread::spawn(move || {
            match format!("{}:0", full).to_socket_addrs() {
                Ok(addrs) => {
                    let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect::<HashSet<_>>().into_iter().collect();
                    if !ips.is_empty() {
                        let _ = tx.send((full, ips));
                    }
                }
                Err(_) => {}
            }
        }));
    }
    drop(tx);
    for h in handles { let _ = h.join(); }
    
    let mut subs: Vec<_> = rx.into_iter().collect();
    subs.sort_by(|a, b| a.0.cmp(&b.0));
    
    if !subs.is_empty() {
        hit(&format!("{} subdomains found:", subs.len()));
        for (sub, ips) in &subs {
            println!("  {} {:<40} → {}", clr(c::G, "[FOUND]"), sub, ips.join(", "));
            r.log(&format!("{} → {}", sub, ips.join(", ")));
        }
    } else {
        warn("No subdomains resolved");
    }

    // SSL/TLS Certificate info
    sep("SSL/TLS CERTIFICATE");
    let ssl_host = domain.split(':').next().unwrap_or(&domain);
    info(&format!("Checking certificate for {}:443", ssl_host));
    
    let ssl_result = if which("openssl") {
        run_cmd("openssl", &["s_client", "-connect", &format!("{}:443", ssl_host), "-servername", ssl_host, "-showcerts"])
    } else {
        run_cmd("powershell", &["-Command", &format!(
            "try {{ $c = New-Object System.Net.Sockets.TcpClient('{}', 443); $s = New-Object System.Net.Security.SslStream($c.GetStream()); $s.AuthenticateAsClient('{}'); $cert = $s.RemoteCertificate; \"Subject: $($cert.Subject)`nIssuer: $($cert.Issuer)`nValidFrom: $($cert.GetEffectiveDateString())`nValidTo: $($cert.GetExpirationDateString())`nThumbprint: $($cert.GetCertHashString())\" }} catch {{ 'SSL check failed: ' + $_.Exception.Message }}",
            ssl_host, ssl_host
        )])
    };
    
    match ssl_result {
        Some(text) => {
            for line in text.lines() {
                if line.contains("Subject:") || line.contains("Issuer:") || line.contains("Valid") 
                   || line.contains("Thumbprint") || line.contains("Protocol:") || line.contains("Cipher:") {
                    ok(line);
                    r.log(line);
                }
            }
            // Check expiry
            if text.contains("ValidTo:") {
                // Parse and compare dates would go here
                ok("Certificate expiry check: manual review recommended");
            }
        }
        None => warn("SSL inspection failed. Install openssl or check firewall"),
    }

    if let Err(e) = r.save() { err(&format!("Save failed: {}", e)); }
}

// ═══════════════════════════════════════════════════════════════
//  MODULE 4: URL SCANNER (Headers + Security + Redirects)
// ═══════════════════════════════════════════════════════════════
fn module_url_scanner(target: &str) {
    let mut r = match Report::new("url_scanner", target) { Ok(r) => r, Err(e) => { err(&format!("Report error: {}", e)); return; } };
    sep("URL SECURITY SCANNER");
    
    let url = if target.starts_with("http") { target.to_string() } else { format!("https://{}", target) };
    info(&format!("Scanning: {}", clr(c::W, &url)));

    // Follow redirects manually to show chain
    let mut current_url = url.clone();
    let mut redirect_count = 0;
    let max_redirects = 5;
    
    loop {
        if redirect_count >= max_redirects {
            warn("Max redirects reached - possible redirect loop");
            break;
        }
        
        match ureq::get(&current_url)
            .set("User-Agent", "Mozilla/5.0 AEGIS-CTI/2.0")
            .timeout(Duration::from_secs(10))
            .call() {
            Ok(resp) => {
                let status = resp.status();
                ok(&format!("Status: {} {}", status, status_text(status)));
                r.log(&format!("Status: {}", status));
                
                // Headers
                sep("RESPONSE HEADERS");
                let headers = resp.headers_names();
                for name in &headers {
                    if let Some(val) = resp.header(name) {
                        ok(&format!("{}: {}", format!("{:<30}", name), &val[..80.min(val.len())]));
                        r.log(&format!("{}: {}", name, val));
                    }
                }
                
                // Security headers audit
                sep("SECURITY HEADER AUDIT");
                let sec_headers = [
                    ("Strict-Transport-Security", "HSTS - forces HTTPS"),
                    ("Content-Security-Policy", "CSP - XSS protection"),
                    ("X-Frame-Options", "Clickjacking protection"),
                    ("X-Content-Type-Options", "MIME sniffing protection"),
                    ("Referrer-Policy", "Referrer leakage control"),
                    ("Permissions-Policy", "Feature access control"),
                    ("X-XSS-Protection", "Legacy XSS filter"),
                    ("Cross-Origin-Opener-Policy", "Cross-origin isolation"),
                ];
                
                for (header, description) in &sec_headers {
                    let present = headers.iter().any(|h| h.eq_ignore_ascii_case(header));
                    let status = if present { 
                        let val = resp.header(header).unwrap_or("");
                        if val.is_empty() {
                            clr(c::Y, "PRESENT (empty)")
                        } else {
                            clr(c::G, "PRESENT")
                        }
                    } else {
                        clr(c::R, "MISSING")
                    };
                    println!("  {} {:<36} {}", 
                        if present { clr(c::G, "[+]") } else { clr(c::R, "[-]") },
                        format!("{:<30}", header),
                        status
                    );
                    r.log(&format!("{}: {}", header, if present { "PRESENT" } else { "MISSING" }));
                }
                
                // Server fingerprinting
                if let Some(server) = resp.header("Server") {
                    info(&format!("Server fingerprint: {}", server));
                    r.log(&format!("Server: {}", server));
                }
                if let Some(powered) = resp.header("X-Powered-By") {
                    warn(&format!("X-Powered-By exposes: {}", powered));
                    r.log(&format!("X-Powered-By: {}", powered));
                }
                
                break;
            }
            Err(ureq::Error::Status(301, resp)) | Err(ureq::Error::Status(302, resp)) |
            Err(ureq::Error::Status(307, resp)) | Err(ureq::Error::Status(308, resp)) => {
                if let Some(loc) = resp.header("Location") {
                    info(&format!("Redirect {} → {}", redirect_count + 1, loc));
                    r.log(&format!("Redirect {} → {}", redirect_count + 1, loc));
                    current_url = if loc.starts_with("http") { loc.to_string() } else { 
                        format!("{}/{}", url.trim_end_matches('/'), loc.trim_start_matches('/'))
                    };
                    redirect_count += 1;
                } else {
                    err("Redirect without Location header");
                    break;
                }
            }
            Err(ureq::Error::Status(code, _)) => {
                err(&format!("HTTP {}", code));
                r.log(&format!("HTTP Error: {}", code));
                break;
            }
            Err(e) => {
                err(&format!("Request failed: {}", e));
                break;
            }
        }
    }

    if let Err(e) = r.save() { err(&format!("Save failed: {}", e)); }
}

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK", 201 => "Created", 204 => "No Content",
        301 => "Moved Permanently", 302 => "Found", 307 => "Temporary Redirect", 308 => "Permanent Redirect",
        400 => "Bad Request", 401 => "Unauthorized", 403 => "Forbidden", 404 => "Not Found",
        500 => "Internal Server Error", 502 => "Bad Gateway", 503 => "Service Unavailable",
        _ => "Unknown",
    }
}

// ═══════════════════════════════════════════════════════════════
//  MODULE 5: FILE ANALYZER (PE + Entropy + Strings)
// ═══════════════════════════════════════════════════════════════
fn module_file_analyzer(target: &str) {
    let mut r = match Report::new("file_analyzer", target) { Ok(r) => r, Err(e) => { err(&format!("Report error: {}", e)); return; } };
    sep("FILE ANALYZER");
    
    let path = Path::new(target);
    if !path.exists() {
        err("File not found"); return;
    }
    
    info(&format!("Analyzing: {}", clr(c::W, target)));
    
    let metadata = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => { err(&format!("Cannot read file: {}", e)); return; }
    };
    
    let size = metadata.len();
    ok(&format!("Size: {} bytes ({} KB)", size, size / 1024));
    r.log(&format!("Size: {} bytes", size));
    
    // Read file
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => { err(&format!("Cannot read file: {}", e)); return; }
    };
    
    // Entropy calculation
    let entropy = calculate_entropy(&data);
    let ent_color = if entropy > 7.5 { c::R } else if entropy > 6.0 { c::Y } else { c::G };
    ok(&format!("Entropy: {:.4} {}", entropy, 
        if entropy > 7.5 { "(likely encrypted/packed)" } 
        else if entropy > 6.0 { "(suspicious - possible packing)" } 
        else { "(normal)" }));
    r.log(&format!("Entropy: {:.4}", entropy));
    
    // File type detection (magic bytes)
    let file_type = detect_file_type(&data);
    ok(&format!("Detected type: {}", file_type));
    r.log(&format!("Type: {}", file_type));
    
    // PE analysis
    if file_type == "PE32" || file_type == "PE32+" {
        sep("PE ANALYSIS");
        analyze_pe(&data, &mut r);
    }
    
    // String extraction
    sep("STRING EXTRACTION");
    let strings = extract_strings(&data, 4);
    let mut ioc_strings: Vec<String> = Vec::new();
    
    for s in &strings {
        // IOC pattern detection
        if looks_like_ip(s) || looks_like_url(s) || looks_like_email(s) 
           || s.len() == 32 || s.len() == 40 || s.len() == 64 {
            ioc_strings.push(s.clone());
        }
    }
    
    if !ioc_strings.is_empty() {
        hit(&format!("{} potential IOCs in strings:", ioc_strings.len()));
        for ioc in ioc_strings.iter().take(20) {
            println!("  {} {}", clr(c::M, "[IOC]"), ioc);
            r.log(&format!("IOC: {}", ioc));
        }
        if ioc_strings.len() > 20 {
            dim(&format!("  ... and {} more", ioc_strings.len() - 20));
        }
    }
    
    // All strings sample
    info("Sample strings (first 20):");
    for s in strings.iter().take(20) {
        dim(&format!("  {}", s));
        r.log(&format!("STRING: {}", s));
    }

    if let Err(e) = r.save() { err(&format!("Save failed: {}", e)); }
}

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut freq = [0u64; 256];
    for &b in data { freq[b as usize] += 1; }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&f| f > 0)
        .map(|&f| {
            let p = f as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn detect_file_type(data: &[u8]) -> &'static str {
    if data.len() < 4 { return "Unknown"; }
    match &data[..4] {
        [0x4D, 0x5A, _, _] => {
            if data.len() > 0x3C {
                let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
                if data.len() > pe_offset + 6 && &data[pe_offset..pe_offset+4] == b"PE\0\0" {
                    let machine = u16::from_le_bytes([data[pe_offset+4], data[pe_offset+5]]);
                    return if machine == 0x8664 { "PE32+ (x64)" } else { "PE32 (x86)" };
                }
            }
            "MZ (DOS)"
        }
        [0x7F, b'E', b'L', b'F'] => "ELF",
        [0xCA, 0xFE, 0xBA, 0xBE] => "Mach-O",
        [0x50, 0x4B, 0x03, 0x04] => "ZIP/JAR/DOCX",
        [0x25, 0x50, 0x44, 0x46] => "PDF",
        _ => "Unknown/Binary",
    }
}

fn analyze_pe(data: &[u8], r: &mut Report) {
    if data.len() < 0x40 { return; }
    let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if data.len() < pe_offset + 24 { return; }
    
    // Number of sections
    let num_sections = u16::from_le_bytes([data[pe_offset+6], data[pe_offset+7]]);
    ok(&format!("Sections: {}", num_sections));
    r.log(&format!("Sections: {}", num_sections));
    
    // Timestamp
    let timestamp = u32::from_le_bytes([data[pe_offset+8], data[pe_offset+9], data[pe_offset+10], data[pe_offset+11]]);
    let compile_time = chrono::DateTime::from_timestamp(timestamp as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "Invalid".to_string());
    ok(&format!("Compile time: {}", compile_time));
    r.log(&format!("Compile time: {}", compile_time));
    
    // Check for suspicious characteristics
    let characteristics = u16::from_le_bytes([data[pe_offset+22], data[pe_offset+23]]);
    if characteristics & 0x2000 != 0 {
        warn("DLL file (not executable)");
        r.log("Type: DLL");
    } else {
        ok("Executable file");
        r.log("Type: EXE");
    }
    
    // Section names
    let optional_header_size = u16::from_le_bytes([data[pe_offset+20], data[pe_offset+21]]);
    let section_table = pe_offset + 24 + optional_header_size as usize;
    
    info("Section table:");
    for i in 0..num_sections.min(16) {
        let off = section_table + (i as usize * 40);
        if data.len() < off + 8 { break; }
        let name = String::from_utf8_lossy(&data[off..off+8]).trim_end_matches('\0').to_string();
        let virt_size = u32::from_le_bytes([data[off+8], data[off+9], data[off+10], data[off+11]]);
        let raw_size = u32::from_le_bytes([data[off+16], data[off+17], data[off+18], data[off+19]]);
        let characteristics = u32::from_le_bytes([data[off+36], data[off+37], data[off+38], data[off+39]]);
        
        let exec = if characteristics & 0x20000000 != 0 { clr(c::R, "EXEC") } else { clr(c::DIM, "----") };
        let writable = if characteristics & 0x80000000 != 0 { clr(c::Y, "WRITE") } else { clr(c::DIM, "-----") };
        
        println!("  {:<12} VirtSize:{:>8} RawSize:{:>8}  {}  {}", 
            name, virt_size, raw_size, exec, writable);
        r.log(&format!("Section: {} VirtSize:{} RawSize:{}", name, virt_size, raw_size));
        
        // Suspicious: writable + executable section
        if characteristics & 0xA0000000 == 0xA0000000 {
            crit("  ^^^ RWX section detected - highly suspicious!");
            r.log("ALERT: RWX section detected");
        }
    }
    
    // Import table hint
    info("Import analysis: Use 'pestudio' or 'CFF Explorer' for full import table");
}

fn extract_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = String::new();
    
    for &b in data {
        if b.is_ascii_graphic() || b == b' ' {
            current.push(b as char);
        } else {
            if current.len() >= min_len {
                strings.push(current.clone());
            }
            current.clear();
        }
    }
    if current.len() >= min_len { strings.push(current); }
    strings
}

fn looks_like_ip(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok() || 
    s.split('.').count() == 4 && s.split('.').all(|p| p.parse::<u8>().is_ok())
}

fn looks_like_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://") || 
    (s.contains('.') && (s.ends_with(".com") || s.ends_with(".org") || s.ends_with(".net") || s.ends_with(".ru")))
}

fn looks_like_email(s: &str) -> bool {
    s.contains('@') && s.contains('.') && !s.contains(' ')
}

// ═══════════════════════════════════════════════════════════════
//  MODULE 6: IOC EXTRACTOR
// ═══════════════════════════════════════════════════════════════
fn module_ioc_extractor(target: &str) {
    let mut r = match Report::new("ioc_extractor", target) { Ok(r) => r, Err(e) => { err(&format!("Report error: {}", e)); return; } };
    sep("IOC EXTRACTOR");
    
    let content = if Path::new(target).exists() {
        info(&format!("Reading file: {}", target));
        match fs::read_to_string(target) {
            Ok(c) => c,
            Err(_) => {
                // Try binary read and extract strings
                match fs::read(target) {
                    Ok(data) => extract_strings(&data, 4).join("\n"),
                    Err(e) => { err(&format!("Cannot read: {}", e)); return; }
                }
            }
        }
    } else {
        info("Treating input as raw text...");
        target.to_string()
    };
    
    let mut iocs = HashMap::new();
    
    // IPv4
    let ip_re = regex::Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap();
    let ips: HashSet<String> = ip_re.find_iter(&content).map(|m| m.as_str().to_string()).collect();
    if !ips.is_empty() { iocs.insert("IPv4", ips); }
    
    // Domains
    let domain_re = regex::Regex::new(r"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b").unwrap();
    let domains: HashSet<String> = domain_re.find_iter(&content)
        .map(|m| m.as_str().to_string())
        .filter(|d| !d.starts_with("www.") && d.contains('.') && d.len() > 4)
        .collect();
    if !domains.is_empty() { iocs.insert("Domain", domains); }
    
    // MD5
    let md5_re = regex::Regex::new(r"\b[a-fA-F0-9]{32}\b").unwrap();
    let md5s: HashSet<String> = md5_re.find_iter(&content).map(|m| m.as_str().to_lowercase()).collect();
    if !md5s.is_empty() { iocs.insert("MD5", md5s); }
    
    // SHA1
    let sha1_re = regex::Regex::new(r"\b[a-fA-F0-9]{40}\b").unwrap();
    let sha1s: HashSet<String> = sha1_re.find_iter(&content).map(|m| m.as_str().to_lowercase()).collect();
    if !sha1s.is_empty() { iocs.insert("SHA1", sha1s); }
    
    // SHA256
    let sha256_re = regex::Regex::new(r"\b[a-fA-F0-9]{64}\b").unwrap();
    let sha256s: HashSet<String> = sha256_re.find_iter(&content).map(|m| m.as_str().to_lowercase()).collect();
    if !sha256s.is_empty() { iocs.insert("SHA256", sha256s); }
    
    // Emails
    let email_re = regex::Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap();
    let emails: HashSet<String> = email_re.find_iter(&content).map(|m| m.as_str().to_string()).collect();
    if !emails.is_empty() { iocs.insert("Email", emails); }
    
    // URLs
    let url_re = regex::Regex::new(r"https?://[^\s\"<>]+").unwrap();
    let urls: HashSet<String> = url_re.find_iter(&content).map(|m| m.as_str().to_string()).collect();
    if !urls.is_empty() { iocs.insert("URL", urls); }
    
    // Registry keys
    let reg_re = regex::Regex::new(r"HKEY_[A-Z_]+\\[^\s\"]+").unwrap();
    let regs: HashSet<String> = reg_re.find_iter(&content).map(|m| m.as_str().to_string()).collect();
    if !regs.is_empty() { iocs.insert("Registry", regs); }
    
    // File paths
    let path_re = regex::Regex::new(r"[A-Za-z]:\\[^<>\s\"]+|/[^<>\s\"]+/[a-zA-Z0-9_.-]+").unwrap();
    let paths: HashSet<String> = path_re.find_iter(&content).map(|m| m.as_str().to_string()).collect();
    if !paths.is_empty() { iocs.insert("FilePath", paths); }
    
    // Display results
    for (ioc_type, values) in &iocs {
        hit(&format!("{} {} found", values.len(), ioc_type));
        for v in values.iter().take(10) {
            println!("  {} {}", clr(c::M, "→"), v);
            r.log(&format!("{}: {}", ioc_type, v));
        }
        if values.len() > 10 {
            dim(&format!("  ... and {} more", values.len() - 10));
        }
    }
    
    if iocs.is_empty() {
        warn("No IOCs detected in input");
    } else {
        let total: usize = iocs.values().map(|v| v.len()).sum();
        ok(&format!("Total IOCs extracted: {}", total));
    }

    if let Err(e) = r.save() { err(&format!("Save failed: {}", e)); }
}

// ═══════════════════════════════════════════════════════════════
//  MODULE 7: MITRE ATT&CK MAPPER
// ═══════════════════════════════════════════════════════════════
fn module_mitre_mapper(target: &str) {
    let mut r = match Report::new("mitre_mapper", target) { Ok(r) => r, Err(e) => { err(&format!("Report error: {}", e)); return; } };
    sep("MITRE ATT&CK MAPPER");
    info(&format!("Mapping: {}", clr(c::W, target)));
    
    // Built-in TTP database (subset of common techniques)
    let ttps: HashMap<&str, (&str, &str, &str)> = [
        ("T1566", ("Initial Access", "Phishing", "Spearphishing Attachment")),
        ("T1566.001", ("Initial Access", "Phishing", "Spearphishing Attachment")),
        ("T1566.002", ("Initial Access", "Phishing", "Spearphishing Link")),
        ("T1078", ("Initial Access", "Valid Accounts", "Default/Compromised accounts")),
        ("T1190", ("Initial Access", "Exploit Public-Facing Application", "Web app exploits")),
        ("T1059", ("Execution", "Command and Scripting Interpreter", "PowerShell, CMD, Python")),
        ("T1059.001", ("Execution", "Command and Scripting Interpreter", "PowerShell")),
        ("T1059.003", ("Execution", "Command and Scripting Interpreter", "Windows Command Shell")),
        ("T1053", ("Execution", "Scheduled Task/Job", "Task Scheduler, cron")),
        ("T1053.005", ("Execution", "Scheduled Task/Job", "Scheduled Task/Job")),
        ("T1547", ("Persistence", "Boot or Logon Autostart Execution", "Registry Run keys")),
        ("T1547.001", ("Persistence", "Boot or Logon Autostart Execution", "Registry Run Keys")),
        ("T1053", ("Persistence", "Scheduled Task/Job", "Scheduled tasks for persistence")),
        ("T1071", ("Command and Control", "Application Layer Protocol", "HTTP, HTTPS, DNS")),
        ("T1071.001", ("Command and Control", "Application Layer Protocol", "Web Protocols")),
        ("T1573", ("Command and Control", "Encrypted Channel", "TLS/SSL encrypted C2")),
        ("T1571", ("Command and Control", "Non-Standard Port", "C2 over uncommon ports")),
        ("T1001", ("Command and Control", "Data Obfuscation", "Protocol impersonation")),
        ("T1041", ("Exfiltration", "Exfiltration Over C2 Channel", "Data theft via C2")),
        ("T1048", ("Exfiltration", "Exfiltration Over Alternative Protocol", "DNS tunneling, FTP")),
        ("T1048.003", ("Exfiltration", "Exfiltration Over Alternative Protocol", "Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol")),
        ("T1083", ("Discovery", "File and Directory Discovery", "Enumerating files")),
        ("T1087", ("Discovery", "Account Discovery", "Local/domain account enumeration")),
        ("T1087.001", ("Discovery", "Account Discovery", "Local Account")),
        ("T1018", ("Discovery", "Remote System Discovery", "Network scanning")),
        ("T1057", ("Discovery", "Process Discovery", "Tasklist, ps")),
        ("T1518", ("Discovery", "Software Discovery", "Enumerating installed software")),
        ("T1562", ("Defense Evasion", "Impair Defenses", "Disable security tools")),
        ("T1562.001", ("Defense Evasion", "Impair Defenses", "Disable or Modify Tools")),
        ("T1027", ("Defense Evasion", "Obfuscated Files or Information", "Encoded/encrypted payloads")),
        ("T1070", ("Defense Evasion", "Indicator Removal on Host", "Clear logs, delete files")),
        ("T1070.004", ("Defense Evasion", "Indicator Removal on Host", "File Deletion")),
        ("T1036", ("Defense Evasion", "Masquerading", "Rename malware to look legitimate")),
        ("T1003", ("Credential Access", "OS Credential Dumping", "LSASS, SAM, NTDS.dit")),
        ("T1003.001", ("Credential Access", "OS Credential Dumping", "LSASS Memory")),
        ("T1110", ("Credential Access", "Brute Force", "Password guessing, spraying")),
        ("T1110.003", ("Credential Access", "Brute Force", "Password Spraying")),
        ("T1210", ("Lateral Movement", "Exploitation of Remote Services", "SMB, RDP, SSH exploits")),
        ("T1021", ("Lateral Movement", "Remote Services", "RDP, SSH, SMB, WinRM")),
        ("T1021.001", ("Lateral Movement", "Remote Services", "Remote Desktop Protocol")),
        ("T1021.002", ("Lateral Movement", "Remote Services", "SMB/Windows Admin Shares")),
        ("T1486", ("Impact", "Data Encrypted for Impact", "Ransomware encryption")),
        ("T1490", ("Impact", "Inhibit System Recovery", "Delete backups, disable recovery")),
    ].into_iter().collect();
    
    // Search by technique ID, tactic, or keyword
    let search_lower = target.to_lowercase();
    let mut matches = Vec::new();
    
    for (id, (tactic, technique, subtechnique)) in &ttps {
        if id.to_lowercase().contains(&search_lower) 
           || tactic.to_lowercase().contains(&search_lower)
           || technique.to_lowercase().contains(&search_lower)
           || subtechnique.to_lowercase().contains(&search_lower) {
            matches.push((id, tactic, technique, subtechnique));
        }
    }
    
    if !matches.is_empty() {
        hit(&format!("{} technique(s) matched:", matches.len()));
        for (id, tactic, technique, sub) in matches {
            println!("  {} {}", clr(c::M, id), clr(c::G, &format!("{} → {} → {}", tactic, technique, sub)));
            r.log(&format!("{}: {} → {} → {}", id, tactic, technique, sub));
        }
    } else {
        // Try to suggest based on keywords
        info("No direct match. Searching technique database...");
        info("Common mappings:");
        ok("Phishing → T1566");
        ok("PowerShell → T1059.001");
        ok("Registry Run Keys → T1547.001");
        ok("LSASS Dump → T1003.001");
        ok("RDP Lateral Movement → T1021.001");
        ok("Ransomware → T1486");
    }
    
    sep("MITRE REFERENCE");
    info(&format!("Full database: https://attack.mitre.org/techniques/{}", 
        if target.starts_with("T") { target } else { "" }));
    r.log(&format!("Reference: https://attack.mitre.org/"));

    if let Err(e) = r.save() { err(&format!("Save failed: {}", e)); }
}

// ═══════════════════════════════════════════════════════════════
//  MODULE 8: CVE LOOKUP
// ═══════════════════════════════════════════════════════════════
fn module_cve_lookup(target: &str) {
    let mut r = match Report::new("cve_lookup", target) { Ok(r) => r, Err(e) => { err(&format!("Report error: {}", e)); return; } };
    sep("CVE LOOKUP");
    info(&format!("Querying: {}", clr(c::W, target)));
    
    let cve_id = if target.to_uppercase().starts_with("CVE-") {
        target.to_uppercase()
    } else {
        format!("CVE-{}", target)
    };
    
    // NVD API
    let nvd_url = format!("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}", cve_id);
    match http_get(&nvd_url, 15) {
        Ok(text) => {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                if let Some(vulns) = json.get("vulnerabilities").and_then(|v| v.as_array()) {
                    if let Some(first) = vulns.first() {
                        if let Some(cve) = first.get("cve") {
                            // Description
                            if let Some(descs) = cve.get("descriptions").and_then(|d| d.as_array()) {
                                for desc in descs {
                                    if desc.get("lang").and_then(|l| l.as_str()) == Some("en") {
                                        ok("Description:");
                                        println!("  {}", desc.get("value").and_then(|v| v.as_str()).unwrap_or("N/A"));
                                        r.log(&format!("Description: {}", desc.get("value").and_then(|v| v.as_str()).unwrap_or("N/A")));
                                    }
                                }
                            }
                            
                            // Metrics
                            if let Some(metrics) = cve.get("metrics").and_then(|m| m.get("cvssMetricV31")).and_then(|v| v.as_array()) {
                                if let Some(metric) = metrics.first() {
                                    if let Some(cvss) = metric.get("cvssData") {
                                        let score = cvss.get("baseScore").and_then(|s| s.as_f64()).unwrap_or(0.0);
                                        let severity = cvss.get("baseSeverity").and_then(|s| s.as_str()).unwrap_or("UNKNOWN");
                                        let col = match severity {
                                            "CRITICAL" => c::R, "HIGH" => c::R, "MEDIUM" => c::Y, _ => c::G,
                                        };
                                        ok(&format!("CVSS v3.1 Score: {} {}", clr(col, &score.to_string()), clr(col, severity)));
                                        r.log(&format!("CVSS: {} ({})", score, severity));
                                        
                                        if let Some(vector) = cvss.get("vectorString").and_then(|v| v.as_str()) {
                                            info(&format!("Vector: {}", vector));
                                            r.log(&format!("Vector: {}", vector));
                                        }
                                    }
                                }
                            }
                            
                            // CPEs (affected products)
                            if let Some(configs) = cve.get("configurations").and_then(|c| c.as_array()) {
                                info("Affected products (CPE):");
                                for config in configs {
                                    if let Some(nodes) = config.get("nodes").and_then(|n| n.as_array()) {
                                        for node in nodes {
                                            if let Some(cpes) = node.get("cpeMatch").and_then(|c| c.as_array()) {
                                                for cpe in cpes.take(5) {
                                                    if let Some(criteria) = cpe.get("criteria").and_then(|c| c.as_str()) {
                                                        dim(&format!("  {}", criteria));
                                                        r.log(&format!("CPE: {}", criteria));
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            
                            // References
                            if let Some(refs) = cve.get("references").and_then(|r| r.as_array()) {
                                info("References:");
                                for reference in refs.iter().take(5) {
                                    if let Some(url) = reference.get("url").and_then(|u| u.as_str()) {
                                        dim(&format!("  {}", url));
                                        r.log(&format!("Ref: {}", url));
                                    }
                                }
                            }
                        }
                    }
                } else {
                    warn("CVE not found in NVD database");
                }
            }
        }
        Err(e) => warn(&format!("NVD API error: {}", e)),
    }
    
    // Exploit-DB reference
    sep("EXPLOIT AVAILABILITY");
    info(&format!("Check Exploit-DB: https://www.exploit-db.com/search?cve={}", cve_id));
    info(&format!("Check GitHub: https://github.com/search?q={}", cve_id));
    r.log(&format!("Exploit-DB: https://www.exploit-db.com/search?cve={}", cve_id));

    if let Err(e) = r.save() { err(&format!("Save failed: {}", e)); }
}

// ═══════════════════════════════════════════════════════════════
//  MODULE 9: THREAT ACTOR DB
// ═══════════════════════════════════════════════════════════════
fn module_threat_actor(target: &str) {
    let mut r = match Report::new("threat_actor", target) { Ok(r) => r, Err(e) => { err(&format!("Report error: {}", e)); return; } };
    sep("THREAT ACTOR DATABASE");
    info(&format!("Searching: {}", clr(c::W, target)));
    
    // Embedded threat actor database
    let actors: HashMap<&str, (&str, &str, &[&str], &[&str])> = [
        ("apt1", ("APT1", "China", &["T1071", "T1059", "T1003", "T1021"] as &[&str], &["Comment Crew", "Comment Group", "Shady RAT"] as &[&str])),
        ("apt28", ("APT28", "Russia", &["T1566", "T1059", "T1078", "T1071"], &["Fancy Bear", "Sofacy", "Strontium", "TSAR TEAM"])),
        ("apt29", ("APT29", "Russia", &["T1566", "T1078", "T1059", "T1573"], &["Cozy Bear", "The Dukes", "CozyDuke"])),
        ("apt32", ("APT32", "Vietnam", &["T1566", "T1053", "T1071", "T1041"], &["OceanLotus", "SeaLotus", "Cobalt Kitty"])),
        ("apt33", ("APT33", "Iran", &["T1071", "T1059", "T1486", "T1490"], &["Elfin", "HOLMIUM"])),
        ("apt34", ("APT34", "Iran", &["T1566", "T1071", "T1059", "T1003"], &["OilRig", "Cobalt Gypsy", "HELIX KITTEN"])),
        ("apt35", ("APT35", "Iran", &["T1566", "T1078", "T1059", "T1071"], &["Charming Kitten", "Phosphorus", "Newscaster"])),
        ("apt37", ("APT37", "North Korea", &["T1566", "T1059", "T1071", "T1041"], &["Reaper", "Group123", "ScarCruft"])),
        ("apt38", ("APT38", "North Korea", &["T1078", "T1059", "T1486", "T1048"], &["Lazarus", "Bluenoroff", "BeagleBoyz"])),
        ("apt40", ("APT40", "China", &["T1190", "T1078", "T1059", "T1071"], &["Leviathan", "TEMP.Periscope", "Mudcarp"])),
        ("apt41", ("APT41", "China", &["T1190", "T1078", "T1059", "T1571"], &["Winnti", "Barium", "Wicked Panda"])),
        ("carbanak", ("Carbanak", "Russia", &["T1078", "T1059", "T1486", "T1041"], &["Anunak", "Cobalt Group", "FIN7"])),
        ("fin7", ("FIN7", "Russia", &["T1566", "T1059", "T1078", "T1486"], &["Carbanak", "Navigator", "Anunak"])),
        ("maze", ("Maze", "Unknown", &["T1486", "T1490", "T1078", "T1059"], &["ChaCha ransomware"])),
        ("revil", ("REvil", "Russia", &["T1486", "T1490", "T1078", "T1059"], &["Sodinokibi", "Sodin"])),
        ("darkside", ("DarkSide", "Russia", &["T1486", "T1490", "T1078", "T1041"], &["BlackMatter", "Alphv"])),
        ("conti", ("Conti", "Russia", &["T1486", "T1490", "T1078", "T1021"], &["Wizard Spider", "Ryuk"])),
        ("lockbit", ("LockBit", "Russia", &["T1486", "T1490", "T1078", "T1021"], &["LockBit Black", "LockBit 3.0"])),
        ("lazarus", ("Lazarus Group", "North Korea", &["T1078", "T1059", "T1486", "T1048"], &["Hidden Cobra", "ZINC", "Guardians of Peace"])),
        ("equation", ("Equation Group", "USA", &["T1027", "T1055", "T1071", "T1001"], &["NSA", "TAO"])),
    ].into_iter().collect();
    
    let search_lower = target.to_lowercase();
    let mut matches = Vec::new();
    
    for (key, (name, origin, ttps, aliases)) in &actors {
        if key.contains(&search_lower) 
           || name.to_lowercase().contains(&search_lower)
           || origin.to_lowercase().contains(&search_lower)
           || aliases.iter().any(|a| a.to_lowercase().contains(&search_lower)) {
            matches.push((name, origin, ttps, aliases));
        }
    }
    
    if !matches.is_empty() {
        for (name, origin, ttps, aliases) in matches {
            hit(&format!("{} [{}]", name, origin));
            println!("  {} {}", clr(c::DIM, "Aliases:"), aliases.join(", "));
            r.log(&format!("Actor: {} ({})", name, origin));
            r.log(&format!("Aliases: {}", aliases.join(", ")));
            
            println!("  {} {}", clr(c::DIM, "TTPs:"), ttps.join(", "));
            r.log(&format!("TTPs: {}", ttps.join(", ")));
            
            // Map TTPs to descriptions
            info("Technique details:");
            for ttp in *ttps {
                dim(&format!("  {} - See MITRE ATT&CK database", ttp));
                r.log(&format!("TTP: {}", ttp));
            }
            println!();
        }
    } else {
        warn("Threat actor not found in local database");
        info("Try searching by: name, country, or alias");
        info("Examples: APT28, Fancy Bear, Lazarus, Iran, Russia");
    }
    
    sep("EXTERNAL RESOURCES");
    info(&format!("MITRE Groups: https://attack.mitre.org/groups/"));
    info(&format!("Mandiant: https://www.mandiant.com/resources/blog"));
    r.log("Reference: https://attack.mitre.org/groups/");

    if let Err(e) = r.save() { err(&format!("Save failed: {}", e)); }
}

// ═══════════════════════════════════════════════════════════════
//  MODULE 10: YARA SCANNER
// ═══════════════════════════════════════════════════════════════
fn module_yara_scanner(target: &str) {
    let mut r = match Report::new("yara_scanner", target) { Ok(r) => r, Err(e) => { err(&format!("Report error: {}", e)); return; } };
    sep("YARA SCANNER");
    
    let path = Path::new(target);
    if !path.exists() {
        err("Path not found"); return;
    }
    
    info(&format!("Target: {}", clr(c::W, target)));
    
    // Check for yara binary
    if !which("yara") {
        warn("YARA not found in PATH");
        info("Install YARA: https://github.com/VirusTotal/yara/releases");
        info("Falling back to built-in pattern matching...");
        
        // Built-in simple patterns
        let patterns = [
            ("suspicious_api", b"VirtualAllocEx\x00NtUnmapViewOfSection\x00WriteProcessMemory"),
            ("base64_powershell", b"powershell -e "),
            ("suspicious_url", b"http://"),
            ("suspicious_registry", b"Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
            ("embedded_pe", b"MZ\x90\x00"),
        ];
        
        let data = match fs::read(path) {
            Ok(d) => d,
            Err(e) => { err(&format!("Cannot read: {}", e)); return; }
        };
        
        let mut hits = 0;
        for (name, pattern) in &patterns {
            if data.windows(pattern.len()).any(|window| window == *pattern) {
                hit(&format!("Built-in rule match: {}", name));
                r.log(&format!("MATCH: {}", name));
                hits += 1;
            }
        }
        
        if hits == 0 {
            ok("No built-in pattern matches");
        }
        
        info("For full YARA scanning, install YARA and run:");
        info(&format!("  yara -r rules.yar {}", target));
        
    } else {
        // Use system YARA
        let rules_dir = input("YARA rules directory (Enter for built-in)");
        let rules_path = if rules_dir.is_empty() { "rules.yar" } else { &rules_dir };
        
        let output = run_cmd("yara", &["-r", rules_path, target]);
        match output {
            Some(text) => {
                for line in text.lines() {
                    if !line.trim().is_empty() {
                        hit(line);
                        r.log(line);
                    }
                }
            }
            None => warn("YARA scan failed"),
        }
    }

    if let Err(e) = r.save() { err(&format!("Save failed: {}", e)); }
}

// ═══════════════════════════════════════════════════════════════
//  MODULE 11: WINDOWS EVTX PARSER
// ═══════════════════════════════════════════════════════════════
fn module_evtx_parser(target: &str) {
    let mut r = match Report::new("evtx_parser", target) { Ok(r) => r, Err(e) => { err(&format!("Report error: {}", e)); return; } };
    sep("WINDOWS EVTX PARSER");
    
    let path = Path::new(target);
    if !path.exists() {
        err("File not found"); return;
    }
    
    info(&format!("Parsing: {}", clr(c::W, target)));
    
    // Try using python-evtx or built-in PowerShell fallback
    if which("python") || which("python3") {
        let script = format!(r#"
import sys
try:
    from Evtx.Evtx import Evtx
    from Evtx.Views import evtx_file_xml_view
    import xml.etree.ElementTree as ET
    
    with Evtx(sys.argv[1]) as log:
        count = 0
        for record in log.records():
            count += 1
            if count > 1000:
                print("... truncated at 1000 records")
                break
        print(f"Total records: {{count}}")
except ImportError:
    print("python-evtx not installed. Install: pip install python-evtx")
"#);
        let output = run_cmd("python", &[&script, target]);
        match output {
            Some(text) => {
                for line in text.lines() {
                    if line.contains("Total records") {
                        ok(line);
                    } else {
                        dim(line);
                    }
                    r.log(line);
                }
            }
            None => warn("Python EVTX parsing failed"),
        }
    } else {
        // PowerShell fallback for live event log
        info("Using PowerShell Get-WinEvent fallback...");
        let ps_cmd = format!(
            "Get-WinEvent -Path '{}' -MaxEvents 100 | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message | Format-Table -AutoSize",
            target.replace("'", "''")
        );
        let output = run_cmd("powershell", &["-Command", &ps_cmd]);
        match output {
            Some(text) => {
                for line in text.lines() {
                    if line.contains("Error") || line.contains("Warning") {
                        println!("  {} {}", clr(c::Y, "[!]"), line);
                    } else {
                        dim(&format!("  {}", line));
                    }
                    r.log(line);
                }
            }
            None => warn("PowerShell event log reading failed"),
        }
    }
    
    // Sigma rule correlation hint
    sep("SIGMA CORRELATION");
    info("For Sigma rule correlation, use:");
    info("  sigma convert -t splunk rules/ -p windows");
    info("  or: https://github.com/SigmaHQ/sigma");

    if let Err(e) = r.save() { err(&format!("Save failed: {}", e)); }
}

// ═══════════════════════════════════════════════════════════════
//  MODULE 12: PREFETCH ANALYZER
// ═══════════════════════════════════════════════════════════════
fn module_prefetch(target: &str) {
    let mut r = match Report::new("prefetch", target) { Ok(r) => r, Err(e) => { err(&format!("Report error: {}", e)); return; } };
    sep("PREFETCH ANALYZER");
    
    let path = Path::new(target);
    if !path.exists() {
        err("File not found"); return;
    }
    
    info(&format("Analyzing: {}", clr(c::W, target)));
    
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => { err(&format!("Cannot read: {}", e)); return; }
    };
    
    if data.len() < 4 || &data[..4] != b"MAM\x04" {
        warn("This may not be a valid Prefetch file (expected MAM\\x04 header)");
    }
    
    // Decompress MAM format (simplified - real implementation needs LZNT1/LZXPRESS)
    info("Prefetch format detected");
    info("For full parsing, use:");
    info("  - PECmd (Eric Zimmerman)");
    info("  - WinPrefetchView (NirSoft)");
    info("  - Python: pip install libprefetch");
    
    // Try Python libprefetch
    if which("python") || which("python3") {
        let script = format!(r#"
try:
    import prefetch
    p = prefetch.Prefetch(sys.argv[1])
    print(f"Executable: {{p.executableName}}")
    print(f"Run count: {{p.runCount}}")
    print(f"Last run: {{p.lastRunTime}}")
    for t in p.timestamps[:5]:
        print(f"  Run: {{t}}")
except Exception as e:
    print(f"Error: {{e}}")
"#);
        let output = run_cmd("python", &[&script, target]);
        match output {
            Some(text) => {
                for line in text.lines() {
                    if line.contains("Executable") || line.contains("Run count") || line.contains("Last run") {
                        ok(line);
                    } else {
                        dim(&format!("  {}", line));
                    }
                    r.log(line);
                }
            }
            None => dim("  Python prefetch parsing not available"),
        }
    }
    
    // File metadata
    let metadata = fs::metadata(path).unwrap();
    ok(&format!("File size: {} bytes", metadata.len()));
    ok(&format!("Modified: {:?}", metadata.modified().unwrap_or_else(|_| std::time::SystemTime::UNIX_EPOCH)));
    r.log(&format!("Size: {}", metadata.len()));

    if let Err(e) = r.save() { err(&format!("Save failed: {}", e)); }
}

// ═══════════════════════════════════════════════════════════════
//  MODULE 13: REGISTRY HIVE PARSER
// ═══════════════════════════════════════════════════════════════
fn module_registry(target: &str) {
    let mut r = match Report::new("registry", target) { Ok(r) => r, Err(e) => { err(&format!("Report error: {}", e)); return; } };
    sep("REGISTRY HIVE PARSER");
    
    let path = Path::new(target);
    if !path.exists() {
        err("File not found"); return;
    }
    
    info(&format!("Parsing: {}", clr(c::W, target)));
    
    // Try python-registry
    if which("python") || which("python3") {
        let script = format!(r#"
try:
    from Registry import Registry
    reg = Registry.Registry(sys.argv[1])
    print(f"Hive type: {{reg.hive_type()}}")
    
    # ShimCache
    try:
        shim = reg.open("ControlSet001\\Control\\Session Manager\\AppCompatCache")
        print("ShimCache: Found")
    except:
        print("ShimCache: Not found")
    
    # AmCache
    try:
        amc = reg.open("Root\\InventoryApplication")
        print("AmCache: Found")
    except:
        print("AmCache: Not found")
        
    # UserAssist
    try:
        ua = reg.open("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist")
        print("UserAssist: Found")
    except:
        print("UserAssist: Not found")
        
except Exception as e:
    print(f"Error: {{e}}")
"#);
        let output = run_cmd("python", &[&script, target]);
        match output {
            Some(text) => {
                for line in text.lines() {
                    if line.contains("Found") {
                        hit(line);
                    } else if line.contains("Not found") {
                        dim(&format!("  {}", line));
                    } else {
                        ok(line);
                    }
                    r.log(line);
                }
            }
            None => warn("Python registry parsing failed"),
        }
    } else {
        info("Install python-registry: pip install python-registry");
    }
    
    sep("REGISTRY ARTIFACTS");
    info("Key artifacts to examine:");
    ok("ShimCache - Program execution evidence");
    ok("AmCache - Application compatibility / execution");
    ok("UserAssist - GUI program execution (ROT13 encoded)");
    ok("RecentDocs - Recently accessed documents");
    ok("Run/RunOnce - Persistence mechanisms");
    ok("NTUser.dat\\Software - User-specific artifacts");

    if let Err(e) = r.save() { err(&format!("Save failed: {}", e)); }
}

// ═══════════════════════════════════════════════════════════════
//  MODULE 14: MEMORY STRING SEARCH
// ═══════════════════════════════════════════════════════════════
fn module_memory_strings(target: &str) {
    let mut r = match Report::new("memory_strings", target) { Ok(r) => r, Err(e) => { err(&format!("Report error: {}", e)); return; } };
    sep("MEMORY DUMP STRING SEARCH");
    
    let path = Path::new(target);
    if !path.exists() {
        err("File not found"); return;
    }
    
    info(&format("Analyzing: {}", clr(c::W, target)));
    
    let metadata = fs::metadata(path).unwrap();
    let size = metadata.len();
    ok(&format!("Dump size: {} MB ({} bytes)", size / 1024 / 1024, size));
    r.log(&format!("Size: {} bytes", size));
    
    // Read in chunks to handle large files
    let chunk_size = 10 * 1024 * 1024; // 10MB chunks
    let mut file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) => { err(&format!("Cannot open: {}", e)); return; }
    };
    
    let mut total_strings = 0;
    let mut ioc_hits = Vec::new();
    let mut chunk = vec![0u8; chunk_size];
    let mut bytes_read = 0;
    
    info("Scanning for strings (this may take a while)...");
    
    loop {
        let n = match file.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => { err(&format!("Read error: {}", e)); break; }
        };
        bytes_read += n;
        
        let strings = extract_strings(&chunk[..n], 6);
        total_strings += strings.len();
        
        for s in &strings {
            if looks_like_ip(s) { ioc_hits.push(format!("IP: {}", s)); }
            if looks_like_url(s) { ioc_hits.push(format!("URL: {}", s)); }
            if s.len() == 32 || s.len() == 40 || s.len() == 64 { 
                ioc_hits.push(format!("Hash: {}", s)); 
            }
            if s.contains("HKEY_") { ioc_hits.push(format!("Reg: {}", s)); }
        }
        
        // Progress
        if bytes_read % (50 * 1024 * 1024) == 0 {
            info(&format!("Processed {} MB...", bytes_read / 1024 / 1024));
        }
    }
    
    ok(&format!("Total strings found: {}", total_strings));
    r.log(&format!("Total strings: {}", total_strings));
    
    let unique_iocs: HashSet<String> = ioc_hits.into_iter().collect();
    if !unique_iocs.is_empty() {
        hit(&format!("{} unique IOCs in memory:", unique_iocs.len()));
        for ioc in unique_iocs.iter().take(30) {
            println!("  {} {}", clr(c::M, "→"), ioc);
            r.log(&format!("IOC: {}", ioc));
        }
        if unique_iocs.len() > 30 {
            dim(&format!("  ... and {} more", unique_iocs.len() - 30));
        }
    } else {
        warn("No IOCs found in memory dump");
    }

    if let Err(e) = r.save() { err(&format!("Save failed: {}", e)); }
}

// ═══════════════════════════════════════════════════════════════
//  MODULE 15: CYBERCHEF PIPE
// ═══════════════════════════════════════════════════════════════
fn module_cyberchef(target: &str) {
    let mut r = match Report::new("cyberchef", target) { Ok(r) => r, Err(e) => { err(&format!("Report error: {}", e)); return; } };
    sep("CYBERCHEF PIPE");
    info(&format!("Input: {}", clr(c::W, target)));
    
    println!("\n  {} {}", clr(c::Y, "1."), "Base64 Encode");
    println!("  {} {}", clr(c::Y, "2."), "Base64 Decode");
    println!("  {} {}", clr(c::Y, "3."), "Hex Encode");
    println!("  {} {}", clr(c::Y, "4."), "Hex Decode");
    println!("  {} {}", clr(c::Y, "5."), "URL Encode");
    println!("  {} {}", clr(c::Y, "6."), "URL Decode");
    println!("  {} {}", clr(c::Y, "7."), "MD5 Hash");
    println!("  {} {}", clr(c::Y, "8."), "SHA1 Hash");
    println!("  {} {}", clr(c::Y, "9."), "SHA256 Hash");
    println!("  {} {}", clr(c::Y, "10."), "ROT13");
    println!("  {} {}", clr(c::Y, "11."), "Reverse");
    println!("  {} {}", clr(c::Y, "12."), "XOR (key=0x13)");
    
    let choice = input("Select operation");
    let result = match choice.as_str() {
        "1" => base64::encode(target.as_bytes()),
        "2" => match base64::decode(target) {
            Ok(v) => String::from_utf8_lossy(&v).to_string(),
            Err(_) => "Invalid Base64".to_string(),
        },
        "3" => target.bytes().map(|b| format!("{:02x}", b)).collect::<String>(),
        "4" => match hex_decode(target) {
            Ok(v) => String::from_utf8_lossy(&v).to_string(),
            Err(_) => "Invalid Hex".to_string(),
        },
        "5" => urlencoding::encode(target).to_string(),
        "6" => urlencoding::decode(target).unwrap_or_else(|_| "Invalid URL encoding".into()).to_string(),
        "7" => format!("{:x}", md5::compute(target.as_bytes())),
        "8" => sha1_hash(target),
        "9" => sha256_hash(target),
        "10" => rot13(target),
        "11" => target.chars().rev().collect(),
        "12" => xor_string(target, 0x13),
        _ => { warn("Invalid choice"); return; }
    };
    
    hit(&format!("Result: {}", result));
    r.log(&format!("Input: {}", target));
    r.log(&format!("Operation: {}", choice));
    r.log(&format!("Output: {}", result));
    
    info("For more operations, visit: https://gchq.github.io/CyberChef/");

    if let Err(e) = r.save() { err(&format!("Save failed: {}", e)); }
}

fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 { return Err(()); }
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i+2], 16).map_err(|_| ()))
        .collect()
}

fn sha1_hash(input: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    // Fallback - real SHA1 needs a crypto library
    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    format!("{:016x} (use crypto lib for real SHA1)", hasher.finish())
}

fn sha256_hash(input: &str) -> String {
    // Placeholder - real implementation needs sha2 crate
    format!("(Install sha2 crate for SHA256) {}", input)
}

fn rot13(input: &str) -> String {
    input.chars().map(|c| {
        if c.is_ascii_alphabetic() {
            let base = if c.is_ascii_lowercase() { b'a' } else { b'A' };
            ((c as u8 - base + 13) % 26 + base) as char
        } else {
            c
        }
    }).collect()
}

fn xor_string(input: &str, key: u8) -> String {
    input.bytes().map(|b| (b ^ key) as char).collect()
}

// ═══════════════════════════════════════════════════════════════
//  MODULE 16: TIMELINE GENERATOR
// ═══════════════════════════════════════════════════════════════
fn module_timeline(target: &str) {
    let mut r = match Report::new("timeline", target) { Ok(r) => r, Err(e) => { err(&format!("Report error: {}", e)); return; } };
    sep("TIMELINE GENERATOR");
    
    let path = Path::new(target);
    if !path.exists() {
        err("Directory not found"); return;
    }
    
    info(&format!("Building timeline from: {}", clr(c::W, target)));
    
    let mut events: Vec<(std::time::SystemTime, String, String)> = Vec::new();
    
    fn collect_files(dir: &Path, events: &mut Vec<(std::time::SystemTime, String, String)>) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Ok(metadata) = entry.metadata() {
                    if let Ok(modified) = metadata.modified() {
                        let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                        let ev_type = if metadata.is_dir() { "DIR" } else { "FILE" };
                        events.push((modified, ev_type.to_string(), name));
                    }
                    if metadata.is_dir() {
                        collect_files(&path, events);
                    }
                }
            }
        }
    }
    
    collect_files(path, &mut events);
    events.sort_by(|a, b| a.0.cmp(&b.0));
    
    ok(&format!("{} events collected", events.len()));
    r.log(&format!("Total events: {}", events.len()));
    
    sep("TIMELINE");
    for (time, ev_type, name) in events.iter().take(50) {
        let dt: chrono::DateTime<chrono::Local> = (*time).into();
        let color = match ev_type.as_str() {
            "DIR" => c::CY, _ => c::W,
        };
        println!("  {} {} {}", 
            clr(c::DIM, &dt.format("%Y-%m-%d %H:%M:%S").to_string()),
            clr(color, &format!("[{}]", ev_type)),
            name
        );
        r.log(&format!("{} [{}] {}", dt.format("%Y-%m-%d %H:%M:%S"), ev_type, name));
    }
    
    if events.len() > 50 {
        dim(&format!("  ... and {} more events", events.len() - 50));
    }

    if let Err(e) = r.save() { err(&format!("Save failed: {}", e)); }
}

// ═══════════════════════════════════════════════════════════════
//  MODULE 17: REPORT GENERATOR
// ═══════════════════════════════════════════════════════════════
fn module_report_generator(_target: &str) {
    sep("REPORT GENERATOR");
    
    let report_dir = Path::new(REPORT_DIR);
    if !report_dir.exists() {
        warn("No reports found. Run scans first."); return;
    }
    
    let entries = match fs::read_dir(report_dir) {
        Ok(e) => e,
        Err(_) => { warn("Cannot read report directory"); return; }
    };
    
    let mut files: Vec<_> = entries
        .flatten()
        .filter(|e| e.path().extension().map(|ex| ex == "txt").unwrap_or(false))
        .filter_map(|e| {
            let path = e.path();
            let name = path.file_name()?.to_string_lossy().to_string();
            let size = fs::metadata(&path).ok()?.len();
            Some((path, name, size))
        })
        .collect();
    
    files.sort_by(|a, b| b.0.metadata().unwrap().modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH)
        .cmp(&a.0.metadata().unwrap().modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH)));
    
    if files.is_empty() { warn("No reports found"); return; }
    
    ok(&format!("Found {} reports", files.len()));
    
    // Generate consolidated report
    let ts = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let out_name = format!("{}/CONSOLIDATED_{}.md", REPORT_DIR, ts);
    
    let mut out = String::new();
    out.push_str("# AEGIS-CTI Consolidated Report\n\n");
    out.push_str(&format!("Generated: {}\n\n", chrono::Local::now().format("%Y-%m-%d %H:%M:%S")));
    out.push_str("---\n\n");
    
    for (path, name, size) in &files {
        out.push_str(&format!("## {}\n\n", name));
        out.push_str(&format!("- Size: {} bytes\n", size));
        if let Ok(content) = fs::read_to_string(path) {
            out.push_str("```\n");
            out.push_str(&content);
            out.push_str("\n```\n\n");
        }
        out.push_str("---\n\n");
    }
    
    match fs::write(&out_name, out) {
        Ok(_) => hit(&format!("Consolidated report saved: {}", out_name)),
        Err(e) => err(&format!("Write failed: {}", e)),
    }
}

// ═══════════════════════════════════════════════════════════════
//  MODULE 18: PHISHING DETECTOR
// ═══════════════════════════════════════════════════════════════
fn module_phishing_detector(target: &str) {
    let mut r = match Report::new("phishing", target) { Ok(r) => r, Err(e) => { err(&format!("Report error: {}", e)); return; } };
    sep("PHISHING DOMAIN DETECTOR");
    info(&format("Analyzing: {}", clr(c::W, target)));
    
    let domain = target.to_lowercase()
        .replace("https://", "")
        .replace("http://", "")
        .split('/')
        .next()
        .unwrap_or(&target)
        .to_string();
    
    // Check for homograph attacks
    let mut homograph_score = 0;
    let suspicious_chars: Vec<char> = domain.chars().filter(|c| {
        // Look for non-ASCII lookalikes
        !c.is_ascii() || matches!(c, '0'|'1'|'і'|'ѕ'|'е'|'о'|'р'|'а'|'ѕ')
    }).collect();
    
    if !suspicious_chars.is_empty() {
        warn(&format!("Suspicious characters detected: {:?}", suspicious_chars));
        homograph_score += 50;
        r.log(&format!("Suspicious chars: {:?}", suspicious_chars));
    }
    
    // Check similarity to common brands
    let brands = ["google", "microsoft", "apple", "amazon", "facebook", "paypal", 
                  "netflix", "bank", "chase", "wellsfargo", "github", "gitlab"];
    let domain_base = domain.split('.').next().unwrap_or(&domain);
    
    for brand in &brands {
        let dist = levenshtein_distance(domain_base, brand);
        if dist > 0 && dist <= 2 {
            crit(&format!("Possible typosquat of '{}': distance={}", brand, dist));
            r.log(&format!("Typosquat: {} → {} (dist={})", domain, brand, dist));
            homograph_score += 30;
        }
    }
    
    // Check for extra subdomains
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() > 3 {
        warn(&format!("Unusual subdomain depth: {} parts", parts.len()));
        homograph_score += 10;
    }
    
    // Check for suspicious TLDs
    let suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".click", ".link"];
    for tld in &suspicious_tlds {
        if domain.ends_with(tld) {
            warn(&format!("Suspicious TLD: {}", tld));
            homograph_score += 15;
        }
    }
    
    // Entropy check (random-looking domains)
    let entropy = calculate_entropy(domain.as_bytes());
    if entropy > 4.0 && domain_base.len() > 10 {
        warn(&format!("High entropy domain (possible DGA): {:.2}", entropy));
        homograph_score += 20;
    }
    
    // Final score
    sep("RISK ASSESSMENT");
    let risk = if homograph_score >= 70 { "HIGH" } 
               else if homograph_score >= 40 { "MEDIUM" } 
               else { "LOW" };
    let risk_col = if homograph_score >= 70 { c::R } else if homograph_score >= 40 { c::Y } else { c::G };
    
    ok(&format!("Phishing risk score: {}/100 ({})", homograph_score, clr(risk_col, risk)));
    r.log(&format!("Score: {}/100 - Risk: {}", homograph_score, risk));
    
    if homograph_score >= 40 {
        crit("This domain shows phishing indicators - verify before interacting!");
    } else {
        ok("No strong phishing indicators detected");
    }

    if let Err(e) = r.save() { err(&format!("Save failed: {}", e)); }
}

fn levenshtein_distance(a: &str, b: &str) -> usize {
    let len_a = a.chars().count();
    let len_b = b.chars().count();
    if len_a == 0 { return len_b; }
    if len_b == 0 { return len_a; }
    
    let mut matrix = vec![vec![0; len_b + 1]; len_a + 1];
    for i in 0..=len_a { matrix[i][0] = i; }
    for j in 0..=len_b { matrix[0][j] = j; }
    
    for (i, ca) in a.chars().enumerate() {
        for (j, cb) in b.chars().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            matrix[i+1][j+1] = (matrix[i][j+1] + 1)
                .min(matrix[i+1][j] + 1)
                .min(matrix[i][j] + cost);
        }
    }
    matrix[len_a][len_b]
}

// ═══════════════════════════════════════════════════════════════
//  MODULE 19: C2 CONFIG EXTRACTOR
// ═══════════════════════════════════════════════════════════════
fn module_c2_extractor(target: &str) {
    let mut r = match Report::new("c2_extractor", target) { Ok(r) => r, Err(e) => { err(&format!("Report error: {}", e)); return; } };
    sep("C2 CONFIG EXTRACTOR");
    
    let path = Path::new(target);
    if !path.exists() {
        err("File not found"); return;
    }
    
    info(&format!("Analyzing: {}", clr(c::W, target)));
    
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => { err(&format!("Cannot read: {}", e)); return; }
    };
    
    // Known C2 patterns
    let patterns = [
        ("URL pattern", regex::Regex::new(r"https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(:[0-9]+)?(/[a-zA-Z0-9._/-]*)?").unwrap()),
        ("IP:Port", regex::Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{2,5}\b").unwrap()),
        ("Base64 blob", regex::Regex::new(r"[A-Za-z0-9+/]{100,}={0,2}").unwrap()),
        ("DGA pattern", regex::Regex::new(r"[a-zA-Z0-9]{20,30}\.[a-zA-Z]{2,6}").unwrap()),
        ("Mutex name", regex::Regex::new(r"Global\\[A-Za-z0-9_-]+").unwrap()),
        ("User-Agent", regex::Regex::new(r"User-Agent:\s*[^\r\n]+").unwrap()),
    ];
    
    let mut total_hits = 0;
    let content = String::from_utf8_lossy(&data);
    
    for (name, re) in &patterns {
        let matches: Vec<&str> = re.find_iter(&content).map(|m| m.as_str()).collect();
        if !matches.is_empty() {
            hit(&format!("{}: {} matches", name, matches.len()));
            for m in matches.iter().take(5) {
                println!("  {} {}", clr(c::M, "→"), m);
                r.log(&format!("{}: {}", name, m));
            }
            if matches.len() > 5 {
                dim(&format!("  ... and {} more", matches.len() - 5));
            }
            total_hits += matches.len();
        }
    }
    
    // Entropy-based packed section detection
    let entropy = calculate_entropy(&data);
    if entropy > 7.0 {
        warn(&format!("High file entropy ({:.2}) - possible packed/encrypted payload", entropy));
        info("Common packers: UPX, Themida, VMProtect, Enigma");
    }
    
    if total_hits == 0 {
        ok("No known C2 patterns detected");
        info("This doesn't mean the sample is benign - use sandbox analysis");
    }

    if let Err(e) = r.save() { err(&format!("Save failed: {}", e)); }
}

// ═══════════════════════════════════════════════════════════════
//  MODULE 20: DARK WEB MONITOR (Paste sites)
// ═══════════════════════════════════════════════════════════════
fn module_darkweb_monitor(target: &str) {
    let mut r = match Report::new("darkweb", target) { Ok(r) => r, Err(e) => { err(&format!("Report error: {}", e)); return; } };
    sep("DARK WEB / PASTE MONITOR");
    info(&format!("Searching for: {}", clr(c::W, target)));
    
    // Note: Real dark web monitoring requires Tor proxy
    // This module queries public paste sites and breach databases
    
    let search_encoded = urlencoding::encode(target);
    
    // Have I Been Pwned (requires API key)
    info("Have I Been Pwned: Configure API key for breach data");
    info(&format!("  Check: https://haveibeenpwned.com/"));
    r.log("HIBP: API key required");
    
    // DeHashed (requires API key)
    info("DeHashed: Configure API key for credential search");
    
    // Public paste search URLs
    sep("PUBLIC PASTE SEARCH");
    let paste_urls = [
        ("Pastebin", format!("https://pastebin.com/search?q={}", search_encoded)),
        ("GitHub Gist", format!("https://gist.github.com/search?q={}", search_encoded)),
        ("GitHub Code", format!("https://github.com/search?q={}&type=code", search_encoded)),
    ];
    
    for (name, url) in &paste_urls {
        println!("  {} {} {}", clr(c::Y, "[URL]"), format!("{:<15}", name), url);
        r.log(&format!("{}: {}", name, url));
    }
    
    // Try to fetch pastebin recent (limited without API)
    info("Attempting pastebin search...");
    match http_get(&format!("https://pastebin.com/search?q={}", search_encoded), 10) {
        Ok(text) => {
            if text.contains("No results") || text.contains("captcha") {
                warn("Pastebin requires CAPTCHA or returned no results");
            } else {
                // Extract paste IDs
                let paste_re = regex::Regex::new(r"/raw/[a-zA-Z0-9]{8}").unwrap();
                let pastes: HashSet<String> = paste_re.find_iter(&text).map(|m| m.as_str().to_string()).collect();
                if !pastes.is_empty() {
                    hit(&format!("{} potential pastes found", pastes.len()));
                    for paste in pastes.iter().take(5) {
                        println!("  {} https://pastebin.com{}", clr(c::M, "→"), paste);
                        r.log(&format!("Paste: https://pastebin.com{}", paste));
                    }
                }
            }
        }
        Err(_) => warn("Pastebin search failed (rate limited or blocked)"),
    }
    
    sep("TOR / DARK WEB");
    info("For .onion monitoring, configure Tor proxy:");
    info("  1. Install Tor Browser or tor service");
    info("  2. Set proxy: 127.0.0.1:9050");
    info("  3. Use: ureq with socks5 proxy");
    r.log("Tor monitoring requires proxy configuration");

    if let Err(e) = r.save() { err(&format!("Save failed: {}", e)); }
}

// ═══════════════════════════════════════════════════════════════
//  MODULE 21: BATCH IOC ENRICH
// ═══════════════════════════════════════════════════════════════
fn module_batch_ioc(target: &str) {
    let mut r = match Report::new("batch_ioc", target) { Ok(r) => r, Err(e) => { err(&format!("Report error: {}", e)); return; } };
    sep("BATCH IOC ENRICHMENT");
    
    let path = Path::new(target);
    if !path.exists() {
        err("File not found"); return;
    }
    
    info(&format!("Processing: {}", clr(c::W, target)));
    
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => { err(&format!("Cannot read: {}", e)); return; }
    };
    
    let lines: Vec<&str> = content.lines().map(|l| l.trim()).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
    ok(&format!("{} IOCs loaded", lines.len()));
    r.log(&format!("Total IOCs: {}", lines.len()));
    
    let mut results = Vec::new();
    
    for (i, line) in lines.iter().enumerate() {
        print!("  {} Processing {}/{}: {}\r", clr(c::CY, "[*]"), i + 1, lines.len(), &line[..40.min(line.len())]);
        let _ = io::stdout().flush();
        
        let ioc_type = detect_ioc_type(line);
        let mut enrichment = HashMap::new();
        enrichment.insert("ioc", line.to_string());
        enrichment.insert("type", ioc_type.to_string());
        
        match ioc_type {
            "IP" => {
                // Quick geo lookup
                let geo_url = format!("https://ipapi.co/{}/country/", line);
                match http_get(&geo_url, 5) {
                    Ok(country) => { enrichment.insert("country", country.trim().to_string()); }
                    Err(_) => {}
                }
            }
            "HASH" => {
                // Check MalwareBazaar
                let mb_url = "https://mb-api.abuse.ch/api/v1/";
                let mb_body = format!("query=get_info&hash={}", line);
                match ureq::post(mb_url)
                    .set("Content-Type", "application/x-www-form-urlencoded")
                    .timeout(Duration::from_secs(5))
                    .send_string(&mb_body) {
                    Ok(resp) => {
                        if let Ok(text) = resp.into_string() {
                            if text.contains("\"query_status\":\"ok\"") {
                                enrichment.insert("malware_bazaar", "POSITIVE".to_string());
                            }
                        }
                    }
                    Err(_) => {}
                }
            }
            "DOMAIN" => {
                enrichment.insert("check", "Use Domain Intel module for full analysis".to_string());
            }
            _ => {}
        }
        
        results.push(enrichment);
    }
    println!();
    
    // Summary
    sep("ENRICHMENT SUMMARY");
    for res in &results {
        let ioc = res.get("ioc").unwrap();
        let typ = res.get("type").unwrap();
        let extra = res.get("country").or_else(|| res.get("malware_bazaar")).unwrap_or(&"N/A".to_string());
        println!("  {} {:<10} {:<36} {}", clr(c::Y, "[IOC]"), typ, ioc, clr(c::G, extra));
        r.log(&format!("{} {} {}", typ, ioc, extra));
    }
    
    ok(&format!("Enriched {} IOCs", results.len()));

    if let Err(e) = r.save() { err(&format!("Save failed: {}", e)); }
}

fn detect_ioc_type(ioc: &str) -> &'static str {
    let s = ioc.trim();
    if s.parse::<IpAddr>().is_ok() || (s.split('.').count() == 4 && s.split('.').all(|p| p.parse::<u8>().is_ok())) {
        "IP"
    } else if s.len() == 32 || s.len() == 40 || s.len() == 64 {
        "HASH"
    } else if s.contains('@') {
        "EMAIL"
    } else if s.starts_with("http://") || s.starts_with("https://") {
        "URL"
    } else if s.contains('.') && !s.contains(' ') {
        "DOMAIN"
    } else {
        "UNKNOWN"
    }
}

// ═══════════════════════════════════════════════════════════════
//  MODULE 22: CORRELATION ENGINE
// ═══════════════════════════════════════════════════════════════
fn module_correlation(target: &str) {
    let mut r = match Report::new("correlation", target) { Ok(r) => r, Err(e) => { err(&format!("Report error: {}", e)); return; } };
    sep("CORRELATION ENGINE");
    info(&format!("Cross-referencing: {}", clr(c::W, target)));
    
    let path = Path::new(target);
    if !path.exists() {
        err("File not found"); return;
    }
    
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => { err(&format!("Cannot read: {}", e)); return; }
    };
    
    // Extract all IOCs
    let mut all_iocs: HashMap<&str, Vec<String>> = HashMap::new();
    
    let ip_re = regex::Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap();
    all_iocs.insert("IP", ip_re.find_iter(&content).map(|m| m.as_str().to_string()).collect());
    
    let domain_re = regex::Regex::new(r"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b").unwrap();
    all_iocs.insert("Domain", domain_re.find_iter(&content).map(|m| m.as_str().to_string()).collect());
    
    let hash_re = regex::Regex::new(r"\b[a-fA-F0-9]{32,64}\b").unwrap();
    all_iocs.insert("Hash", hash_re.find_iter(&content).map(|m| m.as_str().to_lowercase()).collect());
    
    // Find shared infrastructure
    sep("SHARED INFRASTRUCTURE ANALYSIS");
    
    // Group IPs by /24
    let mut subnets: HashMap<String, Vec<String>> = HashMap::new();
    for ip in all_iocs.get("IP").unwrap_or(&Vec::new()) {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() == 4 {
            let subnet = format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2]);
            subnets.entry(subnet).or_default().push(ip.clone());
        }
    }
    
    for (subnet, ips) in &subnets {
        if ips.len() > 1 {
            hit(&format!("Subnet cluster: {} ({} IPs)", subnet, ips.len()));
            for ip in ips {
                println!("  {} {}", clr(c::M, "→"), ip);
                r.log(&format!("Subnet {}: {}", subnet, ip));
            }
        }
    }
    
    // Domain similarity
    let domains = all_iocs.get("Domain").unwrap_or(&Vec::new());
    let mut domain_roots: HashMap<String, Vec<String>> = HashMap::new();
    for domain in domains {
        let root = domain.split('.').rev().take(2).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join(".");
        domain_roots.entry(root).or_default().push(domain.clone());
    }
    
    for (root, doms) in &domain_roots {
        if doms.len() > 1 {
            hit(&format!("Domain cluster: {} ({} subdomains)", root, doms.len()));
            for d in doms.iter().take(10) {
                println!("  {} {}", clr(c::M, "→"), d);
                r.log(&format!("Domain {}: {}", root, d));
            }
        }
    }
    
    // Hash similarity (same length grouping)
    let hashes = all_iocs.get("Hash").unwrap_or(&Vec::new());
    let mut by_len: HashMap<usize, Vec<String>> = HashMap::new();
    for h in hashes {
        by_len.entry(h.len()).or_default().push(h.clone());
    }
    for (len, hlist) in &by_len {
        if hlist.len() > 1 {
            info(&format!("{} hashes of length {} (possible family)", hlist.len(), len));
            r.log(&format!("Hash family (len={}): {} samples", len, hlist.len()));
        }
    }

    if let Err(e) = r.save() { err(&format!("Save failed: {}", e)); }
}

// ═══════════════════════════════════════════════════════════════
//  MODULE 23: SANDBOX SUBMIT
// ═══════════════════════════════════════════════════════════════
fn module_sandbox_submit(target: &str) {
    let mut r = match Report::new("sandbox", target) { Ok(r) => r, Err(e) => { err(&format!("Report error: {}", e)); return; } };
    sep("SANDBOX SUBMISSION");
    
    let path = Path::new(target);
    if !path.exists() {
        err("File not found"); return;
    }
    
    info(&format!("File: {}", clr(c::W, target)));
    let size = fs::metadata(path).unwrap().len();
    ok(&format!("Size: {} bytes", size));
    
    if size > 100 * 1024 * 1024 {
        warn("File >100MB - may exceed sandbox limits");
    }
    
    sep("SUBMISSION URLs");
    println!("  {} {:<20} {}", clr(c::Y, "[1]"), "Hybrid Analysis", "https://www.hybrid-analysis.com/");
    println!("  {} {:<20} {}", clr(c::Y, "[2]"), "Any.Run", "https://app.any.run/");
    println!("  {} {:<20} {}", clr(c::Y, "[3]"), "VirusTotal", "https://www.virustotal.com/gui/home/upload");
    println!("  {} {:<20} {}", clr(c::Y, "[4]"), "Joe Sandbox", "https://www.joesandbox.com/");
    println!("  {} {:<20} {}", clr(c::Y, "[5]"), "Triage", "https://tria.ge/");
    
    r.log("Hybrid Analysis: https://www.hybrid-analysis.com/");
    r.log("Any.Run: https://app.any.run/");
    r.log("VirusTotal: https://www.virustotal.com/");
    
    info("For automated submission, configure API keys:");
    info("  - Hybrid Analysis: https://www.hybrid-analysis.com/docs/api/v2");
    info("  - Any.Run: https://any.run/api-documentation/");
    
    // File hash for quick VT lookup
    let data = fs::read(path).unwrap();
    let hash = format!("{:x}", md5::compute(&data));
    ok(&format!("MD5: {} - Check VT first before submitting", hash));
    info(&format!("  https://www.virustotal.com/gui/file/{}", hash));

    if let Err(e) = r.save() { err(&format!("Save failed: {}", e)); }
}

// ═══════════════════════════════════════════════════════════════
//  MODULE 24: GOOGLE DORK GENERATOR
// ═══════════════════════════════════════════════════════════════
fn module_dorks(target: &str) {
    let mut r = match Report::new("dorks", target) { Ok(r) => r, Err(e) => { err(&format!("Report error: {}", e)); return; } };
    sep("GOOGLE DORK GENERATOR");
    
    let domain = target.replace("https://", "").replace("http://", "").split('/').next().unwrap_or(target).to_string();
    info(&format!("Domain: {}", clr(c::W, &domain)));
    
    let dorks = [
        ("Login pages", format!("site:{} inurl:login OR inurl:signin OR inurl:admin", domain)),
        ("Config files", format!("site:{} ext:xml OR ext:conf OR ext:cfg OR ext:ini OR ext:env", domain)),
        ("Database files", format!("site:{} ext:sql OR ext:dbf OR ext:mdb", domain)),
        ("Log files", format!("site:{} ext:log", domain)),
        ("Backup files", format!("site:{} ext:bkp OR ext:bak OR ext:old OR ext:backup", domain)),
        ("PHP info", format!("site:{} ext:php intitle:phpinfo", domain)),
        ("Directory listing", format!(r#"site:{} intitle:"index of" "parent directory""#, domain)),
        ("Exposed .git", format!(r#"site:{} inurl:"/.git""#, domain)),
        ("Env files", format!(r#"site:{} inurl:".env" OR inurl:".env.local""#, domain)),
        ("WordPress", format!("site:{} inurl:wp-content OR inurl:wp-includes", domain)),
        ("Subdomains", format!("site:*.{}", domain)),
        ("AWS S3", format!(r#""{}" site:s3.amazonaws.com"#, domain)),
        ("Juicy files", format!("site:{} ext:pem OR ext:key OR ext:ppk", domain)),
        ("Swagger/API docs", format!("site:{} inurl:swagger OR inurl:api-docs", domain)),
        ("Error messages", format!(r#"site:{} "Warning:" OR "Fatal error" OR "Stack trace""#, domain)),
        ("Spreadsheets", format!("site:{} ext:xls OR ext:xlsx OR ext:csv", domain)),
        ("Documents", format!("site:{} ext:pdf OR ext:doc OR ext:docx", domain)),
        ("SQL errors", format!(r#"site:{} "You have an error in your SQL syntax""#, domain)),
        ("WordPress admin", format!("site:{} inurl:wp-admin", domain)),
        ("Joomla", format!("site:{} inurl:com_users OR inurl:com_admin", domain)),
    ];
    
    for (i, (label, dork)) in dorks.iter().enumerate() {
        println!("  {} {:<22} {}", 
            clr(c::Y, &format!("{:>2}", i + 1)),
            clr(c::DIM, label),
            clr(c::G, dork)
        );
        r.log(&format!("{}: {}", label, dork));
    }
    
    sep("");
    println!("  {} {}", clr(c::CY, "→"), format!("https://www.google.com/search?q=site%3A{}", domain));

    if let Err(e) = r.save() { err(&format!("Save failed: {}", e)); }
}

// ═══════════════════════════════════════════════════════════════
//  MODULE 25: FULL CTI RECON
// ═══════════════════════════════════════════════════════════════
fn module_full_recon(target: &str) {
    sep("FULL CTI RECONNAISSANCE");
    warn("Running all applicable modules — this will take several minutes.");
    info(&format!("Target: {}", clr(c::W, target)));
    
    let modules: Vec<(&str, Box<dyn Fn()>)> = vec![
        ("Hash Analyzer", Box::new(|| module_hash(target))),
        ("IP Reputation", Box::new(|| module_ip_reputation(target))),
        ("Domain Intel", Box::new(|| module_domain_intel(target))),
        ("URL Scanner", Box::new(|| module_url_scanner(target))),
        ("MITRE Mapper", Box::new(|| module_mitre_mapper(target))),
        ("CVE Lookup", Box::new(|| module_cve_lookup(target))),
        ("Threat Actor", Box::new(|| module_threat_actor(target))),
        ("Google Dorks", Box::new(|| module_dorks(target))),
    ];
    
    for (name, func) in modules {
        println!("\n  {}", clr(c::Y, &format!("━━━ {} ━━━", name)));
        func();
    }
    
    sep("FULL RECON COMPLETE");
    ok(&format!("All reports saved to ./{}/", REPORT_DIR));
    ok(&format!("Finished: {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S")));
}

// ═══════════════════════════════════════════════════════════════
//  MODULE 26: VIEW REPORTS
// ═══════════════════════════════════════════════════════════════
fn module_view_reports() {
    sep("SAVED REPORTS");
    
    let base = Path::new(REPORT_DIR);
    let entries = match fs::read_dir(base) {
        Ok(e) => e,
        Err(_) => { warn("No reports yet."); return; }
    };
    
    let mut files: Vec<_> = entries
        .flatten()
        .filter(|e| e.path().extension().map(|ex| ex == "txt").unwrap_or(false))
        .filter_map(|e| {
            let path = e.path();
            let size = fs::metadata(&path).ok()?.len();
            Some((path, size))
        })
        .collect();
    
    files.sort_by(|a, b| b.0.file_name().cmp(&a.0.file_name()));
    
    if files.is_empty() { warn("No reports found."); return; }
    
    ok(&format!("Found {} reports:\n", files.len()));
    for (i, (path, size)) in files.iter().enumerate() {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let size_str = if *size > 1024 { format!("{}KB", size / 1024) } else { format!("{}B", size) };
        println!("  {} {} {}", 
            clr(c::Y, &format!("{:>3}", i + 1)),
            clr(c::G, &format!("{:<55}", name)),
            clr(c::DIM, &size_str)
        );
    }
    
    sep("");
    let choice = input("Enter number to read (Enter to skip)");
    if let Ok(idx) = choice.parse::<usize>() {
        if idx > 0 && idx <= files.len() {
            println!();
            match fs::read_to_string(&files[idx - 1].0) {
                Ok(content) => println!("{}", content),
                Err(e) => err(&format!("Could not read: {}", e)),
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  UTILITIES
// ═══════════════════════════════════════════════════════════════
fn run_cmd(cmd: &str, args: &[&str]) -> Option<String> {
    let output = if cfg!(target_os = "windows") {
        std::process::Command::new("cmd").arg("/c").arg(cmd).args(args).output()
    } else {
        std::process::Command::new(cmd).args(args).output()
    };
    output.ok().map(|o| String::from_utf8_lossy(&o.stdout).to_string())
}

fn which(tool: &str) -> bool {
    let cmd = if cfg!(target_os = "windows") { "where" } else { "which" };
    run_cmd(cmd, &[tool]).map(|s| !s.trim().is_empty()).unwrap_or(false)
}

// ═══════════════════════════════════════════════════════════════
//  MAIN
// ═══════════════════════════════════════════════════════════════
fn main() {
    banner();
    
    let safe_input = |prompt: &str, func: &dyn Fn(&str)| {
        let raw = input(prompt);
        match validate_target(&raw) {
            Ok(target) => func(&target),
            Err(e) => err(&format!("Invalid target — {}", e)),
        }
    };
    
    let dispatch: HashMap<&str, Box<dyn Fn()>> = [
        ("1",  Box::new(|| safe_input("Hash (MD5/SHA1/SHA256)", &module_hash)) as Box<dyn Fn()>),
        ("2",  Box::new(|| safe_input("IP address", &module_ip_reputation))),
        ("3",  Box::new(|| safe_input("Domain", &module_domain_intel))),
        ("4",  Box::new(|| safe_input("URL", &module_url_scanner))),
        ("5",  Box::new(|| safe_input("File path", &module_file_analyzer))),
        ("6",  Box::new(|| safe_input("File path or text", &module_ioc_extractor))),
        ("7",  Box::new(|| safe_input("Technique ID or keyword", &module_mitre_mapper))),
        ("8",  Box::new(|| safe_input("CVE ID (e.g. 2021-44228)", &module_cve_lookup))),
        ("9",  Box::new(|| safe_input("Actor name or alias", &module_threat_actor))),
        ("10", Box::new(|| safe_input("File/directory to scan", &module_yara_scanner))),
        ("11", Box::new(|| safe_input(".evtx file path", &module_evtx_parser))),
        ("12", Box::new(|| safe_input(".pf file path", &module_prefetch))),
        ("13", Box::new(|| safe_input("Registry hive file", &module_registry))),
        ("14", Box::new(|| safe_input("Memory dump file", &module_memory_strings))),
        ("15", Box::new(|| safe_input("Text to transform", &module_cyberchef))),
        ("16", Box::new(|| safe_input("Directory path", &module_timeline))),
        ("17", Box::new(|| safe_input("(any key to generate)", &module_report_generator))),
        ("18", Box::new(|| safe_input("Domain to analyze", &module_phishing_detector))),
        ("19", Box::new(|| safe_input("Malware sample path", &module_c2_extractor))),
        ("20", Box::new(|| safe_input("Keyword/email/domain", &module_darkweb_monitor))),
        ("21", Box::new(|| safe_input("IOC list file path", &module_batch_ioc))),
        ("22", Box::new(|| safe_input("IOC list file path", &module_correlation))),
        ("23", Box::new(|| safe_input("File to submit", &module_sandbox_submit))),
        ("24", Box::new(|| safe_input("Domain", &module_dorks))),
        ("25", Box::new(|| safe_input("Target (domain/IP/hash)", &module_full_recon))),
        ("26", Box::new(module_view_reports)),
    ].into_iter().collect();
    
    loop {
        menu();
        print!("\n  {} {} ", clr(c::G, "AEGIS-CTI"), clr(c::DIM, ">"));
        let _ = io::stdout().flush();
        
        let mut choice = String::new();
        match io::stdin().read_line(&mut choice) {
            Ok(0) | Err(_) => { println!("\n\n  {}\n", clr(c::Y, "Session terminated.")); break; }
            Ok(_) => {}
        }
        
        let choice = choice.trim();
        println!();
        
        match choice {
            "0" => { println!("\n  {}\n", clr(c::G, "AEGIS-CTI offline.")); break; }
            _ => {
                if let Some(func) = dispatch.get(choice) { func(); }
                else { warn(&format!("Unknown module: {}", choice)); }
            }
        }
        
        print!("\n  {}", clr(c::DIM, "Press Enter to continue..."));
        let _ = io::stdout().flush();
        let mut _pause = String::new();
        let _ = io::stdin().read_line(&mut _pause);
        print!("\x1B[2J\x1B[H");
        banner();
    }
}
