//! Binding adapters to ports. The one place a concrete adapter is named.

use heyl_app::{AppError, Ports, recovery::CodeSource};
use heyl_grpc::{GrpcClient, GrpcConfig};
use heyl_platform::{HeadlessSecretStore, KeyringStore, OsRandom, SystemClock, SystemTerminal};
use heyl_ports::SecretStore;
use zeroize::Zeroizing;

/// Every adapter, owned. `heyl-app` borrows them through [`Ports`].
pub struct Adapters {
    api: GrpcClient,
    store: Box<dyn SecretStore>,
    terminal: SystemTerminal,
    clock: SystemClock,
    random: OsRandom,
}

impl Adapters {
    /// Build the real ones.
    ///
    /// # Errors
    /// [`AppError::Api`] if the TLS stack cannot be initialised.
    pub fn new(endpoint: Option<&str>) -> Result<Self, AppError> {
        let config = GrpcConfig {
            endpoint: endpoint
                .map_or_else(|| heyl_grpc::DEFAULT_ENDPOINT.to_owned(), str::to_owned),
            ..GrpcConfig::default()
        };

        // The headless store is an adapter swap, not a special case threaded
        // through the code: it is what makes CI work on a box with no Secret
        // Service (DESIGN.md §5).
        let store: Box<dyn SecretStore> = if HeadlessSecretStore::is_configured() {
            Box::new(HeadlessSecretStore)
        } else {
            Box::new(KeyringStore)
        };

        Ok(Self {
            api: GrpcClient::new(config)?,
            store,
            terminal: SystemTerminal,
            clock: SystemClock,
            random: OsRandom,
        })
    }

    /// Borrow them as the core expects.
    pub fn ports(&self) -> Ports<'_> {
        Ports {
            api: &self.api,
            store: self.store.as_ref(),
            terminal: &self.terminal,
            clock: &self.clock,
            random: &self.random,
        }
    }
}

/// Where the recovery code comes from.
///
/// The environment first, then the terminal. Never argv — there is no `--code`
/// flag to read it from, on purpose.
pub fn code_source<'a>() -> CodeSource<'a> {
    std::env::var(heyl_app::recovery::CODE_ENV).map_or(CodeSource::Ask("recovery code: "), |code| {
        CodeSource::Given(Zeroizing::new(code))
    })
}
