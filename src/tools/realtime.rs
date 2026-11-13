use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use sysinfo::System;

pub struct RealtimeShield {
    pub is_active: Arc<AtomicBool>,
    pub running: Arc<AtomicBool>,
}

impl RealtimeShield {
    pub fn new() -> Self {
        Self {
            is_active: Arc::new(AtomicBool::new(true)),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn start(&self) {
        if self.running.load(Ordering::SeqCst) {
            return;
        }

        self.running.store(true, Ordering::SeqCst);
        self.is_active.store(true, Ordering::SeqCst);

        let is_active = self.is_active.clone();
        let running = self.running.clone();

        thread::spawn(move || {
            let mut sys = System::new_all();
            let mut known_pids = std::collections::HashSet::new();

            // Initial known processes
            sys.refresh_all();
            for (&pid, _) in sys.processes() {
                known_pids.insert(pid.as_u32());
            }

            while running.load(Ordering::SeqCst) {
                if is_active.load(Ordering::SeqCst) {
                    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

                    for (&pid, proc) in sys.processes() {
                        let p = pid.as_u32();
                        if !known_pids.contains(&p) {
                            known_pids.insert(p);
                            if let Some(exe) = proc.exe() {
                                let path_str = exe.to_string_lossy().to_ascii_lowercase();
                                if path_str.contains("temp\\") || path_str.contains("\\tmp") {
                                    // Detected suspicious execution from temp
                                }
                            }
                        }
                    }
                }

                thread::sleep(Duration::from_secs(3));
            }
        });
    }

    pub fn toggle(&self) -> bool {
        let current = self.is_active.load(Ordering::SeqCst);
        let next = !current;
        self.is_active.store(next, Ordering::SeqCst);
        next
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.is_active.store(false, Ordering::SeqCst);
    }
}
