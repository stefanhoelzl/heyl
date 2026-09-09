//! The terminal.
//!
//! Everything that is not a secret goes to **stderr**, so `$(heyl get x)`
//! captures only what was asked for (DESIGN.md §5).

use std::io::{BufRead as _, IsTerminal as _, Write as _};

use heyl_ports::{PortError, Terminal};
use zeroize::Zeroizing;

/// The real terminal.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemTerminal;

fn unavailable(operation: &'static str, e: &std::io::Error) -> PortError {
    PortError::Unavailable {
        operation,
        reason: e.to_string(),
    }
}

impl Terminal for SystemTerminal {
    fn is_interactive(&self) -> bool {
        std::io::stdin().is_terminal()
    }

    fn prompt_line(&self, prompt: &str) -> Result<String, PortError> {
        let mut err = std::io::stderr();
        write!(err, "{prompt}").map_err(|e| unavailable("write the prompt", &e))?;
        err.flush()
            .map_err(|e| unavailable("write the prompt", &e))?;

        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| unavailable("read from stdin", &e))?;
        Ok(line.trim().to_owned())
    }

    fn prompt_hidden(&self, prompt: &str) -> Result<Zeroizing<String>, PortError> {
        rpassword::prompt_password(prompt)
            .map(Zeroizing::new)
            .map_err(|e| unavailable("read without echo", &e))
    }

    fn read_line(&self) -> Result<Zeroizing<String>, PortError> {
        let mut line = Zeroizing::new(String::new());
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| unavailable("read from stdin", &e))?;
        Ok(Zeroizing::new(line.trim().to_owned()))
    }

    fn note(&self, message: &str) {
        let _ = writeln!(std::io::stderr(), "{message}");
    }
}
