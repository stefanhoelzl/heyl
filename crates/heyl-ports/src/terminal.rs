//! Terminal capabilities: detection, prompts, hidden input.

use zeroize::Zeroizing;

use crate::error::PortError;

/// What the client needs from a terminal.
///
/// M2 uses only the input half. QR rendering arrives with the phone-swipe flow
/// at M4 and is deliberately absent here (DESIGN.md §5).
pub trait Terminal: Send + Sync {
    /// Whether stdin is a TTY — i.e. whether prompting is possible at all.
    fn is_interactive(&self) -> bool;

    /// Prompt on **stderr** and read a line from stdin, echoing it.
    ///
    /// Everything that is not a secret goes to stderr, so `$(heyl ...)`
    /// captures only what was asked for (DESIGN.md §5).
    ///
    /// # Errors
    /// [`PortError::Unavailable`] if stdin is closed or unreadable.
    fn prompt_line(&self, prompt: &str) -> Result<String, PortError>;

    /// Prompt on stderr and read a line **without echoing it**.
    ///
    /// # Errors
    /// [`PortError::Unavailable`] if stdin is closed or unreadable.
    fn prompt_hidden(&self, prompt: &str) -> Result<Zeroizing<String>, PortError>;

    /// Read a line from stdin with no prompt, for piped input.
    ///
    /// # Errors
    /// [`PortError::Unavailable`] if stdin is closed or unreadable.
    fn read_line(&self) -> Result<Zeroizing<String>, PortError>;

    /// Write a line to stderr.
    fn note(&self, message: &str);
}
