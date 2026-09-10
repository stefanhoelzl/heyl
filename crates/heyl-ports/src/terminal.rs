//! Terminal capabilities: detection, prompts, hidden input.

use zeroize::Zeroizing;

use crate::error::PortError;

/// How a pairing code should be drawn.
///
/// Polarity is the failure mode that bites: a code drawn light-on-dark scans
/// on a dark terminal and is a photographic negative on a light one, and it
/// fails *silently* — the block renders, looks right, and no phone will read
/// it (DESIGN.md §5). So it is exposed rather than assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum QrStyle {
    /// Unicode half-blocks: about 37 columns for a pairing URL.
    #[default]
    Utf8,
    /// Two spaces per module — twice as wide, but survives fonts with
    /// non-square cells or ligatures.
    Ascii,
    /// Do not draw it; print the URL only.
    None,
}

/// What the client needs from a terminal.
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

    /// Draw a pairing code on **stderr**, if this terminal can.
    ///
    /// Returns whether anything was drawn: the caller always prints the URL
    /// underneath either way, because that one line is the difference between
    /// a recoverable and an unrecoverable pairing attempt. Implementations
    /// draw nothing when stdout is not a TTY.
    fn render_qr(&self, payload: &str, style: QrStyle) -> bool;
}
