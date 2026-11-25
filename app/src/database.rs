use std::collections::HashMap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::scanner::{ThreatSeverity, ThreatType};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDatabase {
    pub signatures: HashMap<String, ThreatSignature>,
    pub last_updated: DateTime<Utc>,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatSignature {
    pub hash: String,
    pub name: String,
    pub severity: ThreatSeverity,
    pub threat_type: ThreatType,
    pub description: String,
    pub first_seen: DateTime<Utc>,
    pub references: Vec<String>,
}

impl ThreatDatabase {
    pub fn new() -> Self {
        let mut signatures = HashMap::new();
        Self::load_builtin_signatures(&mut signatures);
        
        ThreatDatabase {
            signatures,
            last_updated: Utc::now(),
            version: "1.0.0".to_string(),
        }
    }
    
    fn load_builtin_signatures(db: &mut HashMap<String, ThreatSignature>) {
        // EICAR test file
        db.insert(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
            ThreatSignature {
                hash: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
                name: "EICAR-Test-File".to_string(),
                severity: ThreatSeverity::Medium,
                threat_type: ThreatType::Virus,
                description: "Standard antivirus test file (harmless)".to_string(),
                first_seen: Utc::now(),
                references: vec!["https://www.eicar.org/".to_string()],
            }
        );
        
        // Known malware families (example signatures)
        let known_threats = vec![
            ("d41d8cd98f00b204e9800998ecf8427e", "Generic.Trojan", ThreatSeverity::High, ThreatType::Trojan, "Generic trojan detection"),
            ("5d41402abc4b2a76b9719d911017c592", "Ransomware.CryptoLocker", ThreatSeverity::Critical, ThreatType::Ransomware, "File encryption ransomware"),
            ("098f6bcd4621d373cade4e832627b4f6", "Spyware.Keylogger", ThreatSeverity::High, ThreatType::Spyware, "Keystroke logger"),
            ("e4d909c290d0fb1ca068ffaddf22cbd0", "Worm.Conficker", ThreatSeverity::Critical, ThreatType::Worm, "Network worm"),
            ("e10adc3949ba59abbe56e057f20f883e", "Rootkit.TDSS", ThreatSeverity::Critical, ThreatType::Rootkit, "Bootkit rootkit"),
            ("25d55ad283aa400af464c76d713c07ad", "Adware.Generic", ThreatSeverity::Low, ThreatType::Adware, "Advertising software"),
            ("9e107d9d372bb6826bd81d3542a419d6", "Botnet.Mirai", ThreatSeverity::Critical, ThreatType::Botnet, "IoT botnet"),
            ("7c6a180b36896a0a8c02787eeafb0e4c", "Exploit.BlueKeep", ThreatSeverity::Critical, ThreatType::Exploit, "RDP vulnerability exploit"),
            ("81dc9bdb52d04dc20036dbd8313ed055", "PUA.BrowserToolbar", ThreatSeverity::Low, ThreatType::PUA, "Potentially unwanted browser toolbar"),
        ];
        
        for (hash, name, severity, threat_type, desc) in known_threats {
            db.insert(
                hash.to_string(),
                ThreatSignature {
                    hash: hash.to_string(),
                    name: name.to_string(),
                    severity,
                    threat_type,
                    description: desc.to_string(),
                    first_seen: Utc::now(),
                    references: Vec::new(),
                }
            );
        }
    }
    
    pub fn lookup(&self, hash: &str) -> Option<&ThreatSignature> {
        self.signatures.get(hash)
    }
    
    pub fn add_signature(&mut self, signature: ThreatSignature) {
        self.signatures.insert(signature.hash.clone(), signature);
    }
    
    pub fn update_from_online(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // In a real implementation, this would download signatures from a server
        // For now, simulate an update
        self.last_updated = Utc::now();
        self.version = format!("1.0.{}", self.signatures.len());
        Ok(())
    }
    
    pub fn get_stats(&self) -> DatabaseStats {
        let mut by_type = HashMap::new();
        let mut by_severity = HashMap::new();
        
        for sig in self.signatures.values() {
            *by_type.entry(sig.threat_type.clone()).or_insert(0) += 1;
            *by_severity.entry(sig.severity.clone()).or_insert(0) += 1;
        }
        
        DatabaseStats {
            total_signatures: self.signatures.len(),
            by_type,
            by_severity,
            last_updated: self.last_updated,
            version: self.version.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseStats {
    pub total_signatures: usize,
    pub by_type: HashMap<ThreatType, usize>,
    pub by_severity: HashMap<ThreatSeverity, usize>,
    pub last_updated: DateTime<Utc>,
    pub version: String,
}

impl Default for ThreatDatabase {
    fn default() -> Self {
        Self::new()
    }
}