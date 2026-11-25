use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::scanner::{Scanner, Quarantine, ScanResult, ScanType, ThreatSeverity, ScanProgress};
use crate::database::ThreatDatabase;
use crate::realtime::{RealtimeMonitor, RealtimeAction};

mod scanner;
mod database;
mod realtime;

// ANSI color codes
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const CYAN: &str = "\x1b[36m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const MAGENTA: &str = "\x1b[35m";
const GRAY: &str = "\x1b[90m";

struct App {
    scanner: Arc<Scanner>,
    quarantine: Arc<Mutex<Quarantine>>,
    database: Arc<Mutex<ThreatDatabase>>,
    realtime: Arc<Mutex<RealtimeMonitor>>,
    scan_progress: Arc<Mutex<ScanProgress>>,
    scanning: bool,
    custom_scan_path: String,
    realtime_enabled: bool,
    monitored_paths: Vec<PathBuf>,
    status_message: String,
}

impl App {
    fn new() -> Self {
        let quarantine = Arc::new(Mutex::new(Quarantine::new()));
        let scanner = Arc::new(Scanner::new(quarantine.clone()));
        let database = Arc::new(Mutex::new(ThreatDatabase::new()));
        let realtime = Arc::new(Mutex::new(RealtimeMonitor::new(scanner.clone(), quarantine.clone())));
        let scan_progress = Arc::new(Mutex::new(ScanProgress::default()));

        let mut monitored_paths = Vec::new();
        if let Some(home) = dirs::home_dir() {
            monitored_paths.push(home.join("Downloads"));
            monitored_paths.push(home.join("Desktop"));
        }
        monitored_paths.push(std::env::temp_dir());

        if let Ok(mut rt) = realtime.lock() {
            let _ = rt.start(monitored_paths.clone());
        }

        App {
            scanner,
            quarantine,
            database,
            realtime,
            scan_progress,
            scanning: false,
            custom_scan_path: String::new(),
            realtime_enabled: true,
            monitored_paths,
            status_message: "System protected".to_string(),
        }
    }

    fn clear_screen() {
        print!("\x1b[2J\x1b[H");
        io::stdout().flush().ok();
    }

    fn print_header() {
        println!("{}══════════════════════════════════════════{}", CYAN, RESET);
        println!("{}         {}HERCULES{}         {}", CYAN, BOLD, RESET, CYAN);
        println!("{}══════════════════════════════════════════{}", CYAN, RESET);
        println!();
    }

    fn print_menu() {
        println!("{}MAIN MENU{}", BOLD, RESET);
        println!("{}1.{} Quick Scan", CYAN, RESET);
        println!("{}2.{} Full Scan", CYAN, RESET);
        println!("{}3.{} Custom Scan (choose file/folder)", CYAN, RESET);
        println!("{}4.{} Quarantine", CYAN, RESET);
        println!("{}5.{} Real-time Protection", CYAN, RESET);
        println!("{}6.{} Threat Database", CYAN, RESET);
        println!("{}7.{} Settings", CYAN, RESET);
        println!("{}0.{} Exit", CYAN, RESET);
        println!();
        print!("{}Select option: {}" , YELLOW, RESET);
        io::stdout().flush().ok();
    }

    fn read_input() -> String {
        let mut input = String::new();
        io::stdin().read_line(&mut input).ok();
        input.trim().to_string()
    }

    fn start_scan(&mut self, scan_type: ScanType) {
        if self.scanning {
            println!("{}Already scanning!{}", RED, RESET);
            self.pause();
            return;
        }

        self.scanning = true;
        self.status_message = format!("Starting {:?} scan...", scan_type);
        {
            let mut p = self.scan_progress.lock().unwrap();
            *p = ScanProgress::default();
            p.is_scanning = true;
            p.start_time = Some(Instant::now());
        }

        let scanner = self.scanner.clone();
        let progress = self.scan_progress.clone();
        let progress_loop = self.scan_progress.clone();
        let scan_type_clone = scan_type.clone();
        let custom_path = self.custom_scan_path.clone();

        let start_time = Instant::now();

        let handle = std::thread::spawn(move || {
            let result = match scan_type_clone {
                ScanType::Quick => scanner.quick_scan(progress),
                ScanType::Full => scanner.full_scan(progress),
                ScanType::Custom(_) => {
                    if !custom_path.is_empty() {
                        scanner.custom_scan(&PathBuf::from(custom_path), progress)
                    } else {
                        ScanResult {
                            threats: Vec::new(),
                            files_scanned: 0,
                            duration: std::time::Duration::from_secs(0),
                            scan_type: ScanType::Custom(PathBuf::from("")),
                        }
                    }
                }
            };
            (result, start_time.elapsed())
        });

        // Progress display loop with loading bar - always runs at least once
        loop {
            {
                let p = progress_loop.lock().unwrap();
                let percent = (p.progress * 100.0) as u32;
                let bar_width = 30;
                let filled = (percent as usize * bar_width) / 100;
                let bar: String = (0..bar_width).map(|i| if i < filled { '█' } else { '░' }).collect();
                print!("\r{} [{}] {}% | {} / {} files | {} threats{}",
                    CYAN, bar, percent, p.files_scanned, p.total_files, p.threats_found, RESET);
                io::stdout().flush().ok();
                if !p.is_scanning {
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        // Final frame to show 100%
        {
            let p = progress_loop.lock().unwrap();
            let percent = 100u32;
            let bar_width = 30;
            let filled = bar_width;
            let bar: String = (0..bar_width).map(|i| if i < filled { '█' } else { '░' }).collect();
            print!("\r{} [{}] {}% | {} / {} files | {} threats{}",
                CYAN, bar, percent, p.files_scanned, p.total_files, p.threats_found, RESET);
            io::stdout().flush().ok();
        }
        println!();

        let (result, duration) = handle.join().unwrap();
        self.scanning = false;

        // Store result for reference
        self.status_message = format!("Scan complete: {} threats found", result.threats.len());

        // Show scan summary
        println!();
        println!("{}═══ SCAN RESULTS ═══{}", BOLD, RESET);
        println!("  {}Scan type:{}{} {:?}", GRAY, RESET, CYAN, result.scan_type);
        println!("  {}Files checked:{}{} {}", GRAY, RESET, CYAN, result.files_scanned);
        println!("  {}Threats detected:{}{} {}{}", GRAY, RESET, 
            if result.threats.is_empty() { GREEN } else { RED }, 
            result.threats.len(), RESET);
        println!("  {}Time elapsed:{}{} {:.2}s", GRAY, RESET, CYAN, duration.as_secs_f64());
        println!("{}════════════════════════{}", BOLD, RESET);
        
        if !result.threats.is_empty() {
            println!();
            println!("{}{} Threat(s) Found:{}{}", BOLD, RED, RESET, RESET);
            for t in &result.threats {
                let sev_color = match t.severity {
                    ThreatSeverity::Critical => RED,
                    ThreatSeverity::High => YELLOW,
                    ThreatSeverity::Medium => MAGENTA,
                    ThreatSeverity::Low => GREEN,
                };
                println!("  {} - {} ({:?}, {:?})", sev_color, t.name, t.threat_type, t.severity);
                println!("      {}", t.path.display());
            }
            println!();
            print!("{}Quarantine all threats now? (y/n): {}", YELLOW, RESET);
            io::stdout().flush().ok();
            let ans = Self::read_input();
            if ans.eq_ignore_ascii_case("y") {
                for t in &result.threats {
                    if let Ok(mut q) = self.quarantine.lock() {
                        match q.quarantine(t.clone()) {
                            Ok(_) => println!("  {}Quarantined: {}{}", GREEN, t.name, RESET),
                            Err(e) => println!("  {}Failed to quarantine {}: {}{}", RED, t.name, e, RESET),
                        }
                    }
                }
            }
        }
        self.pause();
    }

    fn pause(&self) {
        println!();
        print!("{}Press Enter to continue...{}" , GRAY, RESET);
        io::stdout().flush().ok();
        let _ = Self::read_input();
    }

    fn run_quick_scan(&mut self) {
        self.start_scan(ScanType::Quick);
    }

    fn run_full_scan(&mut self) {
        self.start_scan(ScanType::Full);
    }

    fn run_custom_scan(&mut self) {
        println!();
        println!("{}CUSTOM SCAN{}", BOLD, RESET);
        println!("{}a.{} Choose file or folder", CYAN, RESET);
        println!("{}b.{} Enter path manually", CYAN, RESET);
        println!("{}c.{} Back", CYAN, RESET);
        print!("{}Select option: {}", YELLOW, RESET);
        io::stdout().flush().ok();
        let choice = Self::read_input();

        match choice.as_str() {
            "a" => {
                if let Some(path) = rfd::FileDialog::new()
                    .set_title("Select file or folder to scan")
                    .pick_file()
                {
                    self.custom_scan_path = path.to_string_lossy().to_string();
                    self.start_scan(ScanType::Custom(PathBuf::from(&self.custom_scan_path)));
                }
            }
            "b" => {
                print!("{}Enter path: {}", YELLOW, RESET);
                io::stdout().flush().ok();
                let path = Self::read_input();
                if !path.is_empty() {
                    self.custom_scan_path = path.clone();
                    self.start_scan(ScanType::Custom(PathBuf::from(&path)));
                }
            }
            _ => {}
        }
    }

    fn show_quarantine(&mut self) {
        loop {
            Self::clear_screen();
            Self::print_header();
            println!("{}QUARANTINE{}", BOLD, RESET);
            println!();

            let items = {
                let q = self.quarantine.lock().unwrap();
                q.items.clone()
            };

            if items.is_empty() {
                println!("Quarantine is empty.");
            } else {
                for (i, item) in items.iter().enumerate() {
                    let sev_color = match item.threat.severity {
                        ThreatSeverity::Critical => RED,
                        ThreatSeverity::High => YELLOW,
                        ThreatSeverity::Medium => MAGENTA,
                        ThreatSeverity::Low => GREEN,
                    };
                    println!("  [{}]{} {}{}", GRAY, i, RESET, item.threat.name);
                    println!("      Type: {:?} | Severity: {}{:?}{} | Path: {}", 
                        GRAY, sev_color, item.threat.severity, RESET, item.original_path.display());
                    println!("      Quarantined: {}", item.quarantined_at.format("%Y-%m-%d %H:%M:%S"));
                }
            }

            println!();
            println!("{}a.{} Restore item", CYAN, RESET);
            println!("{}b.{} Delete item", CYAN, RESET);
            println!("{}c.{} Back", CYAN, RESET);
            print!("{}Select option: {}", YELLOW, RESET);
            io::stdout().flush().ok();
            let choice = Self::read_input();

            match choice.as_str() {
                "a" => {
                    print!("{}Enter item index to restore: {}", YELLOW, RESET);
                    io::stdout().flush().ok();
                    let idx: usize = match Self::read_input().trim().parse() {
                        Ok(n) => n,
                        Err(_) => { println!("{}Invalid index.{}", RED, RESET); self.pause(); continue; }
                    };
                    if let Ok(mut q) = self.quarantine.lock() {
                        match q.restore(idx) {
                            Ok(_) => println!("{}Restored successfully.{}", GREEN, RESET),
                            Err(e) => println!("{}Restore failed: {}{}", RED, e, RESET),
                        }
                    }
                    self.pause();
                }
                "b" => {
                    print!("{}Enter item index to delete: {}", YELLOW, RESET);
                    io::stdout().flush().ok();
                    let idx: usize = match Self::read_input().trim().parse() {
                        Ok(n) => n,
                        Err(_) => { println!("{}Invalid index.{}", RED, RESET); self.pause(); continue; }
                    };
                    if let Ok(mut q) = self.quarantine.lock() {
                        match q.delete(idx) {
                            Ok(_) => println!("{}Deleted successfully.{}", GREEN, RESET),
                            Err(e) => println!("{}Delete failed: {}{}", RED, e, RESET),
                        }
                    }
                    self.pause();
                }
                _ => break,
            }
        }
    }

    fn show_realtime(&mut self) {
        loop {
            Self::clear_screen();
            Self::print_header();
            println!("{}REAL-TIME PROTECTION{}", BOLD, RESET);
            println!();

            let enabled = self.realtime_enabled;
            let status = if enabled { "ACTIVE" } else { "INACTIVE" };
            let status_color = if enabled { GREEN } else { RED };
            println!("  Status: {}{}{}", status_color, status, RESET);
            println!();

            let detections = {
                let rt = self.realtime.lock().unwrap();
                rt.get_recent_detections()
            };

            if detections.is_empty() {
                println!("  No recent detections.");
            } else {
                println!("  {}Recent Detections:{}{}", BOLD, RESET, RESET);
                for d in detections.iter().rev().take(10) {
                    let sev_color = match d.threat.severity {
                        ThreatSeverity::Critical => RED,
                        ThreatSeverity::High => YELLOW,
                        ThreatSeverity::Medium => MAGENTA,
                        ThreatSeverity::Low => GREEN,
                    };
                    let action_color = match d.action_taken {
                        RealtimeAction::Quarantined => GREEN,
                        RealtimeAction::Blocked => RED,
                        RealtimeAction::Allowed => GRAY,
                        RealtimeAction::Monitored => MAGENTA,
                    };
                    println!("  [{}]{} {}", GRAY, d.detected_at.format("%H:%M:%S"), RESET);
                    println!("      Threat: {}{:?}{} - {}{}{}", 
                        sev_color, d.threat.severity, RESET, d.threat.name, RESET, "");
                    println!("      Action: {}{:?}{} | Path: {}", 
                        action_color, d.action_taken, RESET, d.threat.path.display());
                }
            }

            println!();
            println!("{}a.{} Toggle protection ({})", CYAN, RESET, if enabled { "Disable" } else { "Enable" });
            println!("{}b.{} Add monitored path", CYAN, RESET);
            println!("{}c.{} Remove monitored path", CYAN, RESET);
            println!("{}d.{} Back", CYAN, RESET);
            print!("{}Select option: {}", YELLOW, RESET);
            io::stdout().flush().ok();
            let choice = Self::read_input();

            match choice.as_str() {
                "a" => {
                    self.realtime_enabled = !self.realtime_enabled;
                    if let Ok(mut rt) = self.realtime.lock() {
                        if self.realtime_enabled {
                            let _ = rt.start(self.monitored_paths.clone());
                        } else {
                            rt.stop();
                        }
                    }
                    self.status_message = if self.realtime_enabled {
                        "Real-time protection enabled".to_string()
                    } else {
                        "Real-time protection disabled".to_string()
                    };
                }
                "b" => {
                    print!("{}Enter path to monitor: {}", YELLOW, RESET);
                    io::stdout().flush().ok();
                    let path = Self::read_input();
                    let p = PathBuf::from(&path);
                    if p.exists() && !self.monitored_paths.contains(&p) {
                        self.monitored_paths.push(p.clone());
                        if let Ok(mut rt) = self.realtime.lock() {
                            let _ = rt.add_path(p);
                        }
                        println!("{}Path added.{}", GREEN, RESET);
                    } else {
                        println!("{}Invalid path or already monitored.{}", RED, RESET);
                    }
                    self.pause();
                }
                "c" => {
                    print!("{}Enter path to remove: {}", YELLOW, RESET);
                    io::stdout().flush().ok();
                    let path = Self::read_input();
                    let p = PathBuf::from(&path);
                    if let Ok(mut rt) = self.realtime.lock() {
                        rt.remove_path(&p);
                    }
                    self.monitored_paths.retain(|x| x != &p);
                    println!("{}Path removed.{}", GREEN, RESET);
                    self.pause();
                }
                _ => break,
            }
        }
    }

    fn show_database(&self) {
        Self::clear_screen();
        Self::print_header();
        println!("{}THREAT DATABASE{}", BOLD, RESET);
        println!();

        if let Ok(db) = self.database.lock() {
            let stats = db.get_stats();
            println!("  Total signatures: {}", stats.total_signatures);
            println!("  Version: {}", stats.version);
            println!("  Last updated: {}", stats.last_updated.format("%Y-%m-%d %H:%M:%S"));
            println!();

            let signatures: Vec<_> = db.signatures.values().cloned().collect();
            for sig in signatures {
                let sev_color = match sig.severity {
                    ThreatSeverity::Critical => RED,
                    ThreatSeverity::High => YELLOW,
                    ThreatSeverity::Medium => MAGENTA,
                    ThreatSeverity::Low => GREEN,
                };
                println!("  {}Hash:{} {:?}", GRAY, RESET, sig.hash);
                println!("  {}Name:{} {}", GRAY, RESET, sig.name);
                println!("  {}Type:{} {:?} | {}Severity:{:?}{}", 
                    GRAY, RESET, sig.threat_type, sev_color, sig.severity, RESET);
                println!("  {}Description:{} {}", GRAY, RESET, sig.description);
                println!();
            }
        }

        println!("{}a.{} Back", CYAN, RESET);
        print!("{}Select option: {}", YELLOW, RESET);
        io::stdout().flush().ok();
        let _ = Self::read_input();
    }

    fn show_settings(&mut self) {
        loop {
            Self::clear_screen();
            Self::print_header();
            println!("{}SETTINGS{}", BOLD, RESET);
            println!();
            println!("  {}Real-time protection: {}{}{}", 
                GRAY, if self.realtime_enabled { GREEN } else { RED }, 
                if self.realtime_enabled { "Enabled" } else { "Disabled" }, RESET);
            println!("  {}Monitored paths:{}", GRAY, RESET);
            for p in &self.monitored_paths {
                println!("      - {}", p.display());
            }
            println!();
            println!("{}a.{} Toggle real-time protection", CYAN, RESET);
            println!("{}b.{} Add monitored path", CYAN, RESET);
            println!("{}c.{} Back", CYAN, RESET);
            print!("{}Select option: {}", YELLOW, RESET);
            io::stdout().flush().ok();
            let choice = Self::read_input();

            match choice.as_str() {
                "a" => {
                    self.realtime_enabled = !self.realtime_enabled;
                    if let Ok(mut rt) = self.realtime.lock() {
                        if self.realtime_enabled {
                            let _ = rt.start(self.monitored_paths.clone());
                        } else {
                            rt.stop();
                        }
                    }
                }
                "b" => {
                    print!("{}Enter path to monitor: {}", YELLOW, RESET);
                    io::stdout().flush().ok();
                    let path = Self::read_input();
                    let p = PathBuf::from(&path);
                    if p.exists() && !self.monitored_paths.contains(&p) {
                        self.monitored_paths.push(p.clone());
                        if let Ok(mut rt) = self.realtime.lock() {
                            let _ = rt.add_path(p);
                        }
                        println!("{}Path added.{}", GREEN, RESET);
                    } else {
                        println!("{}Invalid path or already monitored.{}", RED, RESET);
                    }
                    self.pause();
                }
                _ => break,
            }
        }
    }

    fn run(mut self) {
        loop {
            Self::clear_screen();
            Self::print_header();
            println!("  Status: {}{}{}", if self.scanning { YELLOW } else { GREEN }, self.status_message, RESET);
            println!();
            Self::print_menu();
            let choice = Self::read_input();

            match choice.as_str() {
                "1" => self.run_quick_scan(),
                "2" => self.run_full_scan(),
                "3" => self.run_custom_scan(),
                "4" => self.show_quarantine(),
                "5" => self.show_realtime(),
                "6" => self.show_database(),
                "7" => self.show_settings(),
                "0" => {
                    println!("{}Goodbye!{}", GREEN, RESET);
                    break;
                }
                _ => {
                    println!("{}Invalid option.{}", RED, RESET);
                    self.pause();
                }
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 {
        match args[1].as_str() {
            "--begin" => {}
            "--help" | "-h" => {
                println!("HERCULES Antivirus");
                println!();
                println!("Usage:");
                println!("  hercules          Start Hercules Antivirus");
                println!("  hercules --begin  Start Hercules Antivirus");
                println!("  hercules --help   Show this help message");
                return;
            }
            _ => {
                println!("{}Unknown argument: {}{}", RED, args[1], RESET);
                println!("Run 'hercules --help' for usage.");
                return;
            }
        }
    }

    let app = App::new();
    app.run();
}
