//! The terminal.
//!
//! Everything that is not a secret goes to **stderr**, so `$(heyl get x)`
//! captures only what was asked for (DESIGN.md §5).

use std::io::{BufRead as _, IsTerminal as _, Write as _};

use heyl_ports::{PortError, QrStyle, Terminal};
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

/// The four-module quiet zone a scanner needs.
///
/// A flush-to-edge code is unreadable by most phones, and it fails silently:
/// the block renders and simply will not scan (DESIGN.md §5).
const QUIET_ZONE: usize = 4;

impl SystemTerminal {
    /// Draw the code with Unicode half-blocks, two module rows per text row.
    ///
    /// Dark modules are drawn as *foreground* here, which is the polarity a
    /// light-background terminal needs. It is the wrong way round on a dark
    /// background, which is why [`QrStyle::Ascii`] and the printed URL exist.
    fn draw(code: &qrcode::QrCode, style: QrStyle) -> String {
        let colors = code.to_colors();
        let width = code.width();
        let quiet = width + QUIET_ZONE * 2;
        let dark = |x: usize, y: usize| -> bool {
            let (Some(x), Some(y)) = (x.checked_sub(QUIET_ZONE), y.checked_sub(QUIET_ZONE)) else {
                return false;
            };
            x < width && y < width && colors[y * width + x] == qrcode::Color::Dark
        };

        let mut out = String::new();
        match style {
            QrStyle::Ascii => {
                for y in 0..quiet {
                    for x in 0..quiet {
                        out.push_str(if dark(x, y) { "██" } else { "  " });
                    }
                    out.push('\n');
                }
            }
            // `None` never reaches here — `render_qr` returns before drawing —
            // but the port is `#[non_exhaustive]`, so this arm is the default.
            _ => {
                for y in (0..quiet).step_by(2) {
                    for x in 0..quiet {
                        out.push(match (dark(x, y), dark(x, y + 1)) {
                            (true, true) => '█',
                            (true, false) => '▀',
                            (false, true) => '▄',
                            (false, false) => ' ',
                        });
                    }
                    out.push('\n');
                }
            }
        }
        out
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

    /// Drawn on **stderr**, and gated on stderr: the stream it writes to is
    /// the stream that has to be a terminal. It used to test stdout, which
    /// meant `heyl --format json session create | jq` — the one invocation a
    /// wrapper actually makes — silently lost the code, while stdout never
    /// received a byte of the drawing either way.
    fn render_qr(&self, payload: &str, style: QrStyle) -> bool {
        if style == QrStyle::None || !std::io::stderr().is_terminal() {
            return false;
        }
        let Ok(code) = qrcode::QrCode::new(payload.as_bytes()) else {
            return false;
        };
        let drawing = Self::draw(&code, style);
        let mut err = std::io::stderr();
        write!(err, "{drawing}").is_ok() && err.flush().is_ok()
    }

    fn note(&self, message: &str) {
        let _ = writeln!(std::io::stderr(), "{message}");
    }
}
