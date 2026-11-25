use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use walkdir::WalkDir;
use sha2::{Digest, Sha256};
use hex;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sysinfo::{System};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {
    pub name: String,
    pub severity: ThreatSeverity,
    pub path: PathBuf,
    pub hash: String,
    pub detected_at: DateTime<Utc>,
    pub threat_type: ThreatType,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ThreatType {
    Virus,
    Trojan,
    Worm,
    Ransomware,
    Spyware,
    Adware,
    Rootkit,
    Keylogger,
    Botnet,
    Exploit,
    PUA,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub threats: Vec<Threat>,
    pub files_scanned: u64,
    pub duration: Duration,
    pub scan_type: ScanType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanType {
    Quick,
    Full,
    Custom(PathBuf),
}

pub struct Scanner {
    threat_db: Arc<Mutex<HashMap<String, ThreatSignature>>>,
    quarantine: Arc<Mutex<Quarantine>>,
    scan_stats: Arc<Mutex<ScanStats>>,
}

#[derive(Debug, Clone)]
pub struct ThreatSignature {
    pub hash: String,
    pub name: String,
    pub severity: ThreatSeverity,
    pub threat_type: ThreatType,
    pub description: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ScanStats {
    pub files_scanned: u64,
    pub threats_found: u64,
    pub last_scan: Option<DateTime<Utc>>,
    pub total_scan_time: Duration,
}

/// Progress information for a running scan
#[derive(Debug, Clone, Default)]
pub struct ScanProgress {
    pub current_file: String,
    pub files_scanned: u64,
    pub total_files: u64,
    pub progress: f32, // 0.0 to 1.0
    pub threats_found: u64,
    pub is_scanning: bool,
    pub scan_type: Option<ScanType>,
    pub start_time: Option<Instant>,
}

impl Scanner {
    pub fn new(quarantine: Arc<Mutex<Quarantine>>) -> Self {
        let mut signatures = HashMap::new();
        Self::load_default_signatures(&mut signatures);
        
        Scanner {
            threat_db: Arc::new(Mutex::new(signatures)),
            quarantine,
            scan_stats: Arc::new(Mutex::new(ScanStats::default())),
        }
    }
    
    fn load_default_signatures(db: &mut HashMap<String, ThreatSignature>) {
        // EICAR test file signature
        db.insert(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
            ThreatSignature {
                hash: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
                name: "EICAR-Test-File".to_string(),
                severity: ThreatSeverity::Medium,
                threat_type: ThreatType::Virus,
                description: "Standard antivirus test file".to_string(),
            }
        );
        
        // Common malware hashes (examples)
        db.insert(
            "d41d8cd98f00b204e9800998ecf8427e".to_string(),
            ThreatSignature {
                hash: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
                name: "Generic.Trojan".to_string(),
                severity: ThreatSeverity::High,
                threat_type: ThreatType::Trojan,
                description: "Generic trojan detection".to_string(),
            }
        );
        
        db.insert(
            "5d41402abc4b2a76b9719d911017c592".to_string(),
            ThreatSignature {
                hash: "5d41402abc4b2a76b9719d911017c592".to_string(),
                name: "Ransomware.CryptoLocker".to_string(),
                severity: ThreatSeverity::Critical,
                threat_type: ThreatType::Ransomware,
                description: "File encryption ransomware".to_string(),
            }
        );
    }
    
    pub fn scan_file(&self, path: &Path) -> Option<Threat> {
        if let Ok(hash) = self.compute_hash(path) {
            let db = self.threat_db.lock().unwrap();
            if let Some(sig) = db.get(&hash) {
                return Some(Threat {
                    name: sig.name.clone(),
                    severity: sig.severity.clone(),
                    path: path.to_path_buf(),
                    hash: hash.clone(),
                    detected_at: Utc::now(),
                    threat_type: sig.threat_type.clone(),
                    description: sig.description.clone(),
                });
            }
        }
        None
    }
    
    fn compute_hash(&self, path: &Path) -> Result<String, std::io::Error> {
        use std::fs::File;
        use std::io::Read;
        
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0; 8192];
        
        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }
        
        Ok(hex::encode(hasher.finalize()))
    }
    
    /// Quick scan with progress reporting
    pub fn quick_scan(&self, progress: Arc<Mutex<ScanProgress>>) -> ScanResult {
        let start = Instant::now();
        let mut threats = Vec::new();
        let mut files_scanned = 0u64;
        
        // Initialize progress
        {
            let mut p = progress.lock().unwrap();
            p.is_scanning = true;
            p.scan_type = Some(ScanType::Quick);
            p.start_time = Some(start);
            p.files_scanned = 0;
            p.threats_found = 0;
            p.current_file = "Starting...".to_string();
        }
        
        // Scan common locations for quick scan
        let quick_paths = vec![
            dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join("Downloads"),
            dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join("Desktop"),
            std::env::temp_dir(),
        ];
        
        // Count total files first for progress
        let mut total_files = 0u64;
        for path in &quick_paths {
            if path.exists() {
                for entry in WalkDir::new(path).max_depth(3).into_iter().filter_map(|e| e.ok()) {
                    if entry.file_type().is_file() {
                        total_files += 1;
                    }
                }
            }
        }
        
        {
            let mut p = progress.lock().unwrap();
            p.total_files = total_files;
        }
        
        for path in quick_paths {
            if path.exists() {
                for entry in WalkDir::new(&path).max_depth(3).into_iter().filter_map(|e| e.ok()) {
                    if entry.file_type().is_file() {
                        files_scanned += 1;
                        let file_path = entry.path().to_string_lossy().to_string();
                        
                        // Update progress
                        {
                            let mut p = progress.lock().unwrap();
                            p.files_scanned = files_scanned;
                            p.current_file = file_path.clone();
                            p.progress = if total_files > 0 { files_scanned as f32 / total_files as f32 } else { 0.0 };
                        }
                        
                        if let Some(threat) = self.scan_file(entry.path()) {
                            threats.push(threat);
                            let mut p = progress.lock().unwrap();
                            p.threats_found += 1;
                        }
                    }
                }
            }
        }
        
        let duration = start.elapsed();
        
        let mut stats = self.scan_stats.lock().unwrap();
        stats.files_scanned += files_scanned;
        stats.threats_found += threats.len() as u64;
        stats.last_scan = Some(Utc::now());
        stats.total_scan_time += duration;
        
        // Final progress update
        {
            let mut p = progress.lock().unwrap();
            p.is_scanning = false;
            p.progress = 1.0;
            p.current_file = "Complete".to_string();
        }
        
        ScanResult {
            threats,
            files_scanned,
            duration,
            scan_type: ScanType::Quick,
        }
    }
    
    /// Full scan with progress reporting
    pub fn full_scan(&self, progress: Arc<Mutex<ScanProgress>>) -> ScanResult {
        let start = Instant::now();
        let mut threats = Vec::new();
        let mut files_scanned = 0u64;
        
        // Initialize progress
        {
            let mut p = progress.lock().unwrap();
            p.is_scanning = true;
            p.scan_type = Some(ScanType::Full);
            p.start_time = Some(start);
            p.files_scanned = 0;
            p.threats_found = 0;
            p.current_file = "Starting...".to_string();
        }
        
        // Scan entire home directory
        let mut total_files = 0u64;
        if let Some(home) = dirs::home_dir() {
            // Count files first
            for entry in WalkDir::new(&home).into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    total_files += 1;
                }
            }
        }
        
        {
            let mut p = progress.lock().unwrap();
            p.total_files = total_files;
        }
        
        if let Some(home) = dirs::home_dir() {
            for entry in WalkDir::new(&home).into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    files_scanned += 1;
                    let file_path = entry.path().to_string_lossy().to_string();
                    
                    // Update progress
                    {
                        let mut p = progress.lock().unwrap();
                        p.files_scanned = files_scanned;
                        p.current_file = file_path.clone();
                        p.progress = if total_files > 0 { files_scanned as f32 / total_files as f32 } else { 0.0 };
                    }
                    
                    if let Some(threat) = self.scan_file(entry.path()) {
                        threats.push(threat);
                        let mut p = progress.lock().unwrap();
                        p.threats_found += 1;
                    }
                }
            }
        }
        
        let duration = start.elapsed();
        
        let mut stats = self.scan_stats.lock().unwrap();
        stats.files_scanned += files_scanned;
        stats.threats_found += threats.len() as u64;
        stats.last_scan = Some(Utc::now());
        stats.total_scan_time += duration;
        
        // Final progress update
        {
            let mut p = progress.lock().unwrap();
            p.is_scanning = false;
            p.progress = 1.0;
            p.current_file = "Complete".to_string();
        }
        
        ScanResult {
            threats,
            files_scanned,
            duration,
            scan_type: ScanType::Full,
        }
    }
    
    /// Custom scan with progress reporting
    pub fn custom_scan(&self, path: &Path, progress: Arc<Mutex<ScanProgress>>) -> ScanResult {
        let start = Instant::now();
        let mut threats = Vec::new();
        let mut files_scanned = 0u64;
        
        // Initialize progress
        {
            let mut p = progress.lock().unwrap();
            p.is_scanning = true;
            p.scan_type = Some(ScanType::Custom(path.to_path_buf()));
            p.start_time = Some(start);
            p.files_scanned = 0;
            p.threats_found = 0;
            p.current_file = "Starting...".to_string();
        }
        
        // Count total files
        let mut total_files = 0u64;
        if path.is_file() {
            total_files = 1;
        } else if path.is_dir() {
            for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    total_files += 1;
                }
            }
        }
        
        {
            let mut p = progress.lock().unwrap();
            p.total_files = total_files;
        }
        
        if path.is_file() {
            files_scanned = 1;
            let file_path = path.to_string_lossy().to_string();
            {
                let mut p = progress.lock().unwrap();
                p.files_scanned = 1;
                p.current_file = file_path.clone();
                p.progress = 1.0;
            }
            if let Some(threat) = self.scan_file(path) {
                threats.push(threat);
                let mut p = progress.lock().unwrap();
                p.threats_found += 1;
            }
        } else if path.is_dir() {
            for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    files_scanned += 1;
                    let file_path = entry.path().to_string_lossy().to_string();
                    
                    {
                        let mut p = progress.lock().unwrap();
                        p.files_scanned = files_scanned;
                        p.current_file = file_path.clone();
                        p.progress = if total_files > 0 { files_scanned as f32 / total_files as f32 } else { 0.0 };
                    }
                    
                    if let Some(threat) = self.scan_file(entry.path()) {
                        threats.push(threat);
                        let mut p = progress.lock().unwrap();
                        p.threats_found += 1;
                    }
                }
            }
        }
        
        let duration = start.elapsed();
        
        let mut stats = self.scan_stats.lock().unwrap();
        stats.files_scanned += files_scanned;
        stats.threats_found += threats.len() as u64;
        stats.last_scan = Some(Utc::now());
        stats.total_scan_time += duration;
        
        // Final progress update
        {
            let mut p = progress.lock().unwrap();
            p.is_scanning = false;
            p.progress = 1.0;
            p.current_file = "Complete".to_string();
        }
        
        ScanResult {
            threats,
            files_scanned,
            duration,
            scan_type: ScanType::Custom(path.to_path_buf()),
        }
    }
    
    pub fn get_stats(&self) -> ScanStats {
        self.scan_stats.lock().unwrap().clone()
    }
    
    pub fn add_signature(&self, signature: ThreatSignature) {
        let mut db = self.threat_db.lock().unwrap();
        db.insert(signature.hash.clone(), signature);
    }
    
    pub fn scan_processes(&self) -> Vec<Threat> {
        let mut threats = Vec::new();
        let mut sys = System::new_all();
        sys.refresh_processes();
        
        for (_, process) in sys.processes() {
            if let Some(exe_path) = process.exe() {
                if let Some(threat) = self.scan_file(exe_path) {
                    threats.push(threat);
                }
            }
        }
        
        threats
    }
}

pub struct Quarantine {
    pub items: Vec<QuarantineItem>,
    quarantine_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineItem {
    pub original_path: PathBuf,
    pub quarantine_path: PathBuf,
    pub threat: Threat,
    pub quarantined_at: DateTime<Utc>,
    pub restored: bool,
}

impl Quarantine {
    pub fn new() -> Self {
        let quarantine_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("Hercules")
            .join("quarantine");
        
        std::fs::create_dir_all(&quarantine_dir).ok();
        
        Quarantine {
            items: Vec::new(),
            quarantine_dir,
        }
    }
    
    pub fn quarantine(&mut self, threat: Threat) -> Result<(), std::io::Error> {
        use std::fs;
        
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let file_name = format!("{}_{}", timestamp, threat.path.file_name().unwrap_or_default().to_string_lossy());
        let quarantine_path = self.quarantine_dir.join(&file_name);
        
        // Copy file to quarantine
        fs::copy(&threat.path, &quarantine_path)?;
        
        // Remove original
        fs::remove_file(&threat.path)?;
        
        let item = QuarantineItem {
            original_path: threat.path.clone(),
            quarantine_path: quarantine_path.clone(),
            threat,
            quarantined_at: Utc::now(),
            restored: false,
        };
        
        self.items.push(item);
        Ok(())
    }
    
    pub fn restore(&mut self, index: usize) -> Result<(), std::io::Error> {
        use std::fs;
        
        if index >= self.items.len() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid index"));
        }
        
        let item = &mut self.items[index];
        if item.restored {
            return Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "Already restored"));
        }
        
        fs::copy(&item.quarantine_path, &item.original_path)?;
        item.restored = true;
        Ok(())
    }
    
    pub fn delete(&mut self, index: usize) -> Result<(), std::io::Error> {
        use std::fs;
        
        if index >= self.items.len() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid index"));
        }
        
        let item = &self.items[index];
        fs::remove_file(&item.quarantine_path)?;
        self.items.remove(index);
        Ok(())
    }
}

impl Default for Quarantine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_eicar_detection() {
        let eicar_content = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let path = std::env::temp_dir().join("hercules_eicar_test.txt");
        fs::write(&path, eicar_content).unwrap();
        
        let quarantine = Arc::new(Mutex::new(Quarantine::new()));
        let scanner = Scanner::new(quarantine);
        
        let threat = scanner.scan_file(&path);
        assert!(threat.is_some(), "EICAR test file should be detected");
        let t = threat.unwrap();
        assert_eq!(t.name, "EICAR-Test-File");
        assert_eq!(t.threat_type, ThreatType::Virus);
        
        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_clean_file_not_detected() {
        let path = std::env::temp_dir().join("hercules_clean_test.txt");
        fs::write(&path, b"this is a clean file").unwrap();
        
        let quarantine = Arc::new(Mutex::new(Quarantine::new()));
        let scanner = Scanner::new(quarantine);
        
        let threat = scanner.scan_file(&path);
        assert!(threat.is_none(), "Clean file should not be detected");
        
        fs::remove_file(&path).ok();
    }
}