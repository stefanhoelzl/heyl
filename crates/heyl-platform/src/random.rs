//! The OS random source.

use heyl_ports::RandomSource;
use rand_core::{OsRng, TryRngCore as _};

/// `getrandom`, via `rand_core`'s OS source.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&self, out: &mut [u8]) {
        // A failing OS RNG is not a condition this client can carry on past:
        // every key it would go on to generate would be predictable.
        OsRng
            .try_fill_bytes(out)
            .expect("the operating system's random source is unavailable");
    }
}
