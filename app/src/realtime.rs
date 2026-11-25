use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use notify::{Watcher, RecursiveMode, Event, EventKind};
use std::thread;
use chrono::{DateTime, Utc};
use crate::scanner::{Scanner, Threat, Quarantine};

pub struct RealtimeMonitor {
    scanner: Arc<Scanner>,
    quarantine: Arc<Mutex<Quarantine>>,
    watcher: Option<notify::RecommendedWatcher>,
    monitoring: Arc<Mutex<bool>>,
    monitored_paths: Arc<Mutex<Vec<PathBuf>>>,
    recent_detections: Arc<Mutex<Vec<RealtimeDetection>>>,
}

#[derive(Debug, Clone)]
pub struct RealtimeDetection {
    pub threat: Threat,
    pub detected_at: DateTime<Utc>,
    pub action_taken: RealtimeAction,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RealtimeAction {
    Quarantined,
    Blocked,
    Allowed,
    Monitored,
}

impl RealtimeMonitor {
    pub fn new(scanner: Arc<Scanner>, quarantine: Arc<Mutex<Quarantine>>) -> Self {
        RealtimeMonitor {
            scanner,
            quarantine,
            watcher: None,
            monitoring: Arc::new(Mutex::new(false)),
            monitored_paths: Arc::new(Mutex::new(Vec::new())),
            recent_detections: Arc::new(Mutex::new(Vec::new())),
        }
    }
    
    pub fn start(&mut self, paths: Vec<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
        if *self.monitoring.lock().unwrap() {
            return Ok(());
        }
        
        let scanner = self.scanner.clone();
        let quarantine = self.quarantine.clone();
        let monitoring = self.monitoring.clone();
        let recent_detections = self.recent_detections.clone();
        let monitored_paths = self.monitored_paths.clone();
        
        *monitored_paths.lock().unwrap() = paths.clone();
        
        let (tx, rx) = std::sync::mpsc::channel();
        
        let mut watcher = notify::recommended_watcher(tx)?;
        
        for path in &paths {
            if path.exists() {
                watcher.watch(path, RecursiveMode::Recursive)?;
            }
        }
        
        *self.monitoring.lock().unwrap() = true;
        self.watcher = Some(watcher);
        
        // Spawn monitoring thread
        thread::spawn(move || {
            while *monitoring.lock().unwrap() {
                if let Ok(event) = rx.recv_timeout(Duration::from_millis(100)) {
                    match event {
                        Ok(Event { kind: EventKind::Create(_) | EventKind::Modify(_), paths, .. }) => {
                            for path in paths {
                                if path.is_file() {
                                    if let Some(threat) = scanner.scan_file(&path) {
                                        let action = Self::handle_threat(&threat, &quarantine);
                                        let mut detections = recent_detections.lock().unwrap();
                                        detections.push(RealtimeDetection {
                                            threat: threat.clone(),
                                            detected_at: Utc::now(),
                                            action_taken: action,
                                        });
                                        // Keep only last 100 detections
                                        if detections.len() > 100 {
                                            detections.remove(0);
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        });
        
        Ok(())
    }
    
    fn handle_threat(threat: &Threat, quarantine: &Arc<Mutex<Quarantine>>) -> RealtimeAction {
        match threat.severity {
            crate::scanner::ThreatSeverity::Critical | crate::scanner::ThreatSeverity::High => {
                if let Ok(mut q) = quarantine.lock() {
                    if q.quarantine(threat.clone()).is_ok() {
                        return RealtimeAction::Quarantined;
                    }
                }
                RealtimeAction::Blocked
            }
            crate::scanner::ThreatSeverity::Medium => {
                RealtimeAction::Monitored
            }
            crate::scanner::ThreatSeverity::Low => {
                RealtimeAction::Allowed
            }
        }
    }
    
    pub fn stop(&mut self) {
        *self.monitoring.lock().unwrap() = false;
        self.watcher = None;
    }
    
    pub fn is_monitoring(&self) -> bool {
        *self.monitoring.lock().unwrap()
    }
    
    pub fn get_monitored_paths(&self) -> Vec<PathBuf> {
        self.monitored_paths.lock().unwrap().clone()
    }
    
    pub fn get_recent_detections(&self) -> Vec<RealtimeDetection> {
        self.recent_detections.lock().unwrap().clone()
    }
    
    pub fn add_path(&mut self, path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        if !path.exists() {
            return Err("Path does not exist".into());
        }
        
        let mut paths = self.monitored_paths.lock().unwrap();
        if !paths.contains(&path) {
            paths.push(path.clone());
            
            if *self.monitoring.lock().unwrap() {
                if let Some(watcher) = &mut self.watcher {
                    watcher.watch(&path, RecursiveMode::Recursive)?;
                }
            }
        }
        Ok(())
    }
    
    pub fn remove_path(&mut self, path: &PathBuf) {
        let mut paths = self.monitored_paths.lock().unwrap();
        paths.retain(|p| p != path);
        
        if *self.monitoring.lock().unwrap() {
            if let Some(watcher) = &mut self.watcher {
                let _ = watcher.unwatch(path);
            }
        }
    }
}

impl Drop for RealtimeMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}