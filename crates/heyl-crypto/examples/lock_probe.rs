//! Reports whether `mlock` engages on this machine, and the limit that governs it.
//!
//! Run with `cargo run -p heyl-crypto --example lock_probe`. `heyl-cli` will do
//! the equivalent at startup and warn once when locking is unavailable.

fn main() {
    let seed = heyl_crypto::Seed::from_bytes(&[1u8; 32]);
    println!("seed mlock engaged: {}", seed.is_locked());
    if let Ok(limits) = std::fs::read_to_string("/proc/self/limits")
        && let Some(line) = limits.lines().find(|l| l.contains("locked memory"))
    {
        println!("{}", line.trim());
    }
}
