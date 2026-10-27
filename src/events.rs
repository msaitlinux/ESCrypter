//! Versioned process event stream. Secrets and argv are never serialized here.
use serde_json::{json, Value};
use std::{
    io::{self, Write},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
static ENABLED: AtomicBool = AtomicBool::new(false);
static SEQ: AtomicU64 = AtomicU64::new(0);
pub fn enable(v: bool) {
    ENABLED.store(v, Ordering::Relaxed);
}
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}
pub fn emit(kind: &str, data: Value) {
    if enabled() {
        let message =
            json!({"v":1,"seq":SEQ.fetch_add(1,Ordering::Relaxed)+1,"event":kind,"data":data});
        let mut out = io::stderr().lock();
        let _ = writeln!(out, "{}", message);
    } else if matches!(kind, "phase" | "progress" | "failed" | "signer") {
        eprintln!("{kind}: {data}");
    }
}
