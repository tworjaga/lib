use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::thread::sleep;
use std::time::Duration;

// RTL-SDR USB IDs
const VID: u16 = 0x0bda;
const PID: u16 = 0x2838;

// RTL-SDR registers
const REG_TUNER_GAIN: u8 = 0x05;
const REG_I2C_MADDR: u8 = 0x01;
const REG_I2C_REG: u8 = 0x02;
const REG_I2C_VAL: u8 = 0x03;
const REG_GPIO: u8 = 0x0d;
const REG_SYSCLK: u8 = 0x0a;

// R820T tuner registers
const R820T_IF_VGA: u8 = 0x05;
const R820T_LNA_GAIN: u8 = 0x07;
const R820T_MIXER_GAIN: u8 = 0x08;
const R820T_PLL: u8 = 0x10;

fn main() {
    println!("[*] SIGINT spectrum analyzer initializing...");
    
    // Linux: access via /dev/bus/usb or libusb raw
    let device_path = find_rtlsdr();
    
    match device_path {
        Some(path) => {
            println!("[+] RTL-SDR found at: {}", path);
            let mut sdr = RtlSdr::open(&path).expect("failed to open SDR");
            
            // configure for wideband SIGINT sweep
            sdr.set_sample_rate(2_400_000)?; // 2.4 MSPS
            sdr.set_center_freq(100_000_000)?; // start at 100 MHz
            
            println!("[*] sweeping 70 MHz - 6 GHz band");
            println!("{:-<60}", "");
            
            // frequency sweep pattern
            let bands = sigint_bands();
            let mut fft = FftEngine::new(2048);
            
            for band in &bands {
                println!("[*] tuning {:.3} MHz - {}: {}", 
                    band.start_mhz, band.end_mhz, band.label);
                
                let mut freq = band.start_mhz * 1_000_000.0;
                let step = 1_000_000.0; // 1 MHz steps
                
                while freq < band.end_mhz * 1_000_000.0 {
                    sdr.set_center_freq(freq as u32)?;
                    sleep(Duration::from_millis(50));
                    
                    let samples = sdr.read_samples(8192)?;
                    let power = fft.analyze(&samples);
                    
                    // detect anomalies
                    if let Some(peak) = detect_signal(&power, band.threshold_db) {
                        println!(
                            "\x1B[1;33m[!] SIGNAL DETECTED\x1B[0m  {:.6} MHz  \
                             power: {:.1} dB  bw: {:.0} kHz  {}",
                            freq / 1_000_000.0,
                            peak.power_db,
                            peak.bandwidth_hz / 1000.0,
                            classify_signal(peak, band)
                        );
                    }
                    
                    freq += step;
                }
            }
        }
        None => {
            println!("[-] no RTL-SDR device found");
            println!("[*] falling back to simulated SIGINT data");
            simulate_sigint();
        }
    }
}

fn find_rtlsdr() -> Option<String> {
    // scan /dev/bus/usb for VID/PID match
    let usb_path = "/dev/bus/usb";
    
    if let Ok(entries) = std::fs::read_dir(usb_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Ok(sub) = std::fs::read_dir(&path) {
                    for dev in sub.flatten() {
                        let dev_path = dev.path().to_string_lossy().to_string();
                        if check_usb_id(&dev_path, VID, PID) {
                            return Some(dev_path);
                        }
                    }
                }
            }
        }
    }
    
    // fallback: check common paths
    for i in 0..10 {
        let path = format!("/dev/usb/{}", i);
        if std::path::Path::new(&path).exists() {
            return Some(path);
        }
    }
    
    None
}

fn check_usb_id(path: &str, vid: u16, pid: u16) -> bool {
    // read USB device descriptor
    if let Ok(mut file) = OpenOptions::new().read(true).open(path) {
        let mut buf = [0u8; 18];
        if file.read_exact(&mut buf).is_ok() {
            let dev_vid = u16::from_le_bytes([buf[8], buf[9]]);
            let dev_pid = u16::from_le_bytes([buf[10], buf[11]]);
            return dev_vid == vid && dev_pid == pid;
        }
    }
    false
}

struct RtlSdr {
    fd: File,
    xtal_freq: u32,
}

impl RtlSdr {
    fn open(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        
        let mut sdr = Self { fd, xtal_freq: 28_800_000 };
        sdr.init()?;
        Ok(sdr)
    }
    
    fn init(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // reset device
        self.write_reg(REG_SYSCLK, 0x01)?; // enable sysclk
        sleep(Duration::from_millis(10));
        
        // configure GPIO
        self.write_reg(REG_GPIO, 0x24)?; // GPIO output
        
        // init R820T tuner
        self.i2c_write(0x34, 0x00, 0x00)?; // soft reset
        
        // set default gains
        self.i2c_write(0x34, R820T_IF_VGA, 0x08)?; // IF VGA
        self.i2c_write(0x34, R820T_LNA_GAIN, 0x10)?; // LNA
        self.i2c_write(0x34, R820T_MIXER_GAIN, 0x10)?; // mixer
        
        println!("[+] RTL-SDR initialized");
        Ok(())
    }
    
    fn set_sample_rate(&mut self, rate: u32) -> Result<(), Box<dyn std::error::Error>> {
        // calculate ratio: rate = xtal * (32 * ratio) / 2^22
        let ratio = ((rate as f64 / self.xtal_freq as f64) * (1 << 22) as f64 / 32.0) as u32;
        
        self.write_reg(0x09, (ratio >> 16) as u8)?;
        self.write_reg(0x0a, (ratio >> 8) as u8)?;
        self.write_reg(0x0b, ratio as u8)?;
        
        println!("[*] sample rate set to {} Hz", rate);
        Ok(())
    }
    
    fn set_center_freq(&mut self, freq: u32) -> Result<(), Box<dyn std::error::Error>> {
        // R820T PLL programming
        let vco_freq = freq as f64 * 2.0; // LO = RF * 2 for direct sampling
        
        let nint = (vco_freq / self.xtal_freq as f64) as u32;
        let nfrac = (((vco_freq / self.xtal_freq as f64) - nint as f64) * (1 << 16) as f64) as u32;
        
        self.i2c_write(0x34, R820T_PLL, (nint << 6) as u8)?;
        self.i2c_write(0x34, R820T_PLL + 1, ((nint >> 2) | ((nfrac >> 8) & 0x3F)) as u8)?;
        self.i2c_write(0x34, R820T_PLL + 2, nfrac as u8)?;
        
        Ok(())
    }
    
    fn read_samples(&mut self, count: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut buf = vec![0u8; count * 2]; // I/Q interleaved
        self.fd.read_exact(&mut buf)?;
        Ok(buf)
    }
    
    fn write_reg(&mut self, reg: u8, val: u8) -> Result<(), Box<dyn std::error::Error>> {
        let cmd = [0x00, reg, val];
        self.fd.write_all(&cmd)?;
        Ok(())
    }
    
    fn i2c_write(&mut self, addr: u8, reg: u8, val: u8) -> Result<(), Box<dyn std::error::Error>> {
        self.write_reg(REG_I2C_MADDR, addr)?;
        self.write_reg(REG_I2C_REG, reg)?;
        self.write_reg(REG_I2C_VAL, val)?;
        sleep(Duration::from_millis(1));
        Ok(())
    }
}

struct FftEngine {
    size: usize,
    window: Vec<f64>,
}

impl FftEngine {
    fn new(size: usize) -> Self {
        let window: Vec<f64> = (0..size)
            .map(|i| 0.54 - 0.46 * (2.0 * std::f64::consts::PI * i as f64 / (size - 1) as f64).cos())
            .collect();
        
        Self { size, window }
    }
    
    fn analyze(&mut self, samples: &[u8]) -> Vec<f64> {
        // convert I/Q bytes to complex, apply window, compute power spectrum
        let mut power = vec![0.0f64; self.size];
        
        for i in 0..self.size.min(samples.len() / 2) {
            let i_val = (samples[i * 2] as f64 - 127.5) / 127.5;
            let q_val = (samples[i * 2 + 1] as f64 - 127.5) / 127.5;
            
            let windowed_i = i_val * self.window[i];
            let windowed_q = q_val * self.window[i];
            
            // simplified DFT bin power (real implementation needs FFT)
            power[i] = 10.0 * (windowed_i * windowed_i + windowed_q * windowed_q).log10();
        }
        
        power
    }
}

struct SignalPeak {
    freq_hz: f64,
    power_db: f64,
    bandwidth_hz: f64,
}

fn detect_signal(power: &[f64], threshold: f64) -> Option<SignalPeak> {
    let mut max_power = -100.0;
    let mut max_idx = 0usize;
    
    for (i, &p) in power.iter().enumerate() {
        if p > max_power {
            max_power = p;
            max_idx = i;
        }
    }
    
    if max_power > threshold {
        // estimate bandwidth at -3dB
        let mut low = max_idx;
        let mut high = max_idx;
        
        while low > 0 && power[low] > max_power - 3.0 {
            low -= 1;
        }
        while high < power.len() - 1 && power[high] > max_power - 3.0 {
            high += 1;
        }
        
        Some(SignalPeak {
            freq_hz: max_idx as f64,
            power_db: max_power,
            bandwidth_hz: (high - low) as f64,
        })
    } else {
        None
    }
}

fn classify_signal(peak: SignalPeak, band: &SigintBand) -> &'static str {
    // crude signal classification based on bandwidth and band context
    let bw_khz = peak.bandwidth_hz / 1000.0;
    
    match band.band_type {
        BandType::Cellular => {
            if bw_khz < 200.0 { "GSM control channel" }
            else if bw_khz < 1500.0 { "LTE" }
            else { "5G NR" }
        }
        BandType::Ism => {
            if bw_khz < 1000.0 { "BLE / Zigbee" }
            else if bw_khz < 2000.0 { "WiFi" }
            else { "wideband interference" }
        }
        BandType::Military => "encrypted / burst",
        BandType::Satellite => {
            if bw_khz < 50.0 { "satcom beacon" }
            else { "satcom traffic" }
        }
        _ => "unknown modulation",
    }
}

#[derive(Clone, Copy)]
enum BandType {
    Cellular,
    Ism,
    Military,
    Satellite,
    Navigation,
    Broadcast,
}

struct SigintBand {
    start_mhz: f64,
    end_mhz: f64,
    label: &'static str,
    band_type: BandType,
    threshold_db: f64,
}

fn sigint_bands() -> Vec<SigintBand> {
    vec![
        SigintBand { start_mhz: 70.0, end_mhz: 110.0, label: "FM broadcast / VHF", band_type: BandType::Broadcast, threshold_db: -40.0 },
        SigintBand { start_mhz: 136.0, end_mhz: 174.0, label: "VHF land mobile", band_type: BandType::Military, threshold_db: -50.0 },
        SigintBand { start_mhz: 400.0, end_mhz: 512.0, label: "UHF land mobile", band_type: BandType::Military, threshold_db: -50.0 },
        SigintBand { start_mhz: 700.0, end_mhz: 960.0, label: "cellular / GSM", band_type: BandType::Cellular, threshold_db: -45.0 },
        SigintBand { start_mhz: 1090.0, end_mhz: 1090.0, label: "ADS-B", band_type: BandType::Navigation, threshold_db: -55.0 },
        SigintBand { start_mhz: 1227.0, end_mhz: 1575.0, label: "GPS / GLONASS", band_type: BandType::Navigation, threshold_db: -60.0 },
        SigintBand { start_mhz: 2400.0, end_mhz: 2500.0, label: "ISM / WiFi / BLE", band_type: BandType::Ism, threshold_db: -50.0 },
        SigintBand { start_mhz: 3400.0, end_mhz: 3800.0, label: "5G mid-band", band_type: BandType::Cellular, threshold_db: -45.0 },
        SigintBand { start_mhz: 4500.0, end_mhz: 6000.0, label: "C-band satcom", band_type: BandType::Satellite, threshold_db: -55.0 },
    ]
}

fn simulate_sigint() {
    println!("[*] running simulated SIGINT collection...");
    
    let bands = sigint_bands();
    let mut seed = 0xDEADu64;
    let mut rand = || {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        (seed >> 16) as u32
    };
    
    for _ in 0..50 {
        let band = &bands[(rand() as usize) % bands.len()];
        let freq = band.start_mhz + (rand() as f64 / u32::MAX as f64) * (band.end_mhz - band.start_mhz);
        let power = band.threshold_db + (rand() as f64 / u32::MAX as f64) * 30.0;
        let bw = 10.0 + (rand() as f64 / u32::MAX as f64) * 2000.0;
        
        if power > band.threshold_db {
            println!(
                "\x1B[1;33m[!] SIGNAL\x1B[0m  {:.6} MHz  power: {:.1} dB  bw: {:.0} kHz  {}  {}",
                freq,
                power,
                bw,
                band.label,
                classify_signal(SignalPeak { freq_hz: freq * 1e6, power_db: power, bandwidth_hz: bw * 1000.0 }, band)
            );
        }
        
        sleep(Duration::from_millis(200));
    }
}
