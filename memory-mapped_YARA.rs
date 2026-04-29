use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Clone)]
struct Rule {
    name: String,
    patterns: Vec<Vec<u8>>,
    condition: Condition,
}

#[derive(Clone)]
enum Condition {
    Any,
    All,
    AtLeast(usize),
}

fn main() {
    let target = std::env::args().nth(1)
        .unwrap_or_else(|| {
            eprintln!("usage: yara_lite <file_or_dir>");
            std::process::exit(1);
        });

    // embedded IOC rules — no external rule files needed
    let rules = vec![
        Rule {
            name: "CobaltStrike_Beacon".into(),
            patterns: vec![
                vec![0x4D, 0x5A], // MZ header
                b"beacon".to_vec(),
                b"ReflectiveLoader".to_vec(),
            ],
            condition: Condition::AtLeast(2),
        },
        Rule {
            name: "Mimikatz_Strings".into(),
            patterns: vec![
                b"mimikatz".to_vec(),
                b"sekurlsa::".to_vec(),
                b"kerberos::".to_vec(),
                b"lsadump::".to_vec(),
            ],
            condition: Condition::Any,
        },
        Rule {
            name: "Suspicious_PowerShell".into(),
            patterns: vec![
                b"-enc ".to_vec(),
                b"Invoke-Expression".to_vec(),
                b"DownloadString".to_vec(),
                b"FromBase64String".to_vec(),
                b"bypass".to_vec(),
            ],
            condition: Condition::AtLeast(2),
        },
        Rule {
            name: "Meterpreter_Stub".into(),
            patterns: vec![
                b"metsrv".to_vec(),
                b"stdapi".to_vec(),
                b"priv".to_vec(),
                b"ext_server_".to_vec(),
            ],
            condition: Condition::AtLeast(2),
        },
        Rule {
            name: "AMSI_Bypass".into(),
            patterns: vec![
                b"amsiInitFailed".to_vec(),
                b"AmsiScanBuffer".to_vec(),
                b"AmsiScanString".to_vec(),
                b"System.Management.Automation".to_vec(),
            ],
            condition: Condition::Any,
        },
    ];

    println!("[*] yara-lite scanner loaded");
    println!("[*] rules: {}", rules.len());
    println!("{:-<60}", "");

    let path = Path::new(&target);
    if path.is_file() {
        scan_file(path, &rules);
    } else if path.is_dir() {
        scan_directory(path, &rules);
    } else {
        eprintln!("[-] invalid target: {}", target);
    }
}

fn scan_directory(dir: &Path, rules: &[Rule]) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            println!("[!] cannot read {}: {}", dir.display(), e);
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            scan_file(&path, rules);
        } else if path.is_dir() {
            scan_directory(&path, rules);
        }
    }
}

fn scan_file(path: &Path, rules: &[Rule]) {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return,
    };

    let size = match file.seek(SeekFrom::End(0)) {
        Ok(s) => s as usize,
        Err(_) => return,
    };
    let _ = file.seek(SeekFrom::Start(0));

    // skip huge files
    if size > 100 * 1024 * 1024 {
        return;
    }

    let mut data = vec![0u8; size];
    if file.read_exact(&mut data).is_err() {
        return;
    }

    let mut hits = Vec::new();

    for rule in rules {
        let mut matched = 0;
        let mut found_patterns = Vec::new();

        for pattern in &rule.patterns {
            if boyer_moore(&data, pattern) {
                matched += 1;
                found_patterns.push(String::from_utf8_lossy(pattern).into_owned());
            }
        }

        let triggered = match rule.condition {
            Condition::Any => matched >= 1,
            Condition::All => matched == rule.patterns.len(),
            Condition::AtLeast(n) => matched >= n,
        };

        if triggered {
            hits.push((rule.name.clone(), found_patterns));
        }
    }

    if !hits.is_empty() {
        println!("\x1B[1;31m[ALERT]\x1B[0m {}", path.display());
        for (name, patterns) in hits {
            println!("  rule: \x1B[33m{}\x1B[0m", name);
            for p in patterns {
                let display = if p.len() > 40 {
                    format!("{}... ({} bytes)", &p[..40], p.len())
                } else {
                    p
                };
                println!("    match: {}", display);
            }
        }
        println!();
    }
}

fn boyer_moore(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() { return true; }
    if needle.len() > haystack.len() { return false; }

    // bad character table
    let mut bad_char = [needle.len(); 256];
    for (i, &b) in needle.iter().enumerate().take(needle.len() - 1) {
        bad_char[b as usize] = needle.len() - 1 - i;
    }

    let mut i = needle.len() - 1;
    while i < haystack.len() {
        let mut j = needle.len() - 1;
        let mut k = i;

        while haystack[k] == needle[j] {
            if j == 0 { return true; }
            j -= 1;
            k -= 1;
        }

        i += bad_char[haystack[i] as usize].max(1);
    }

    false
}
