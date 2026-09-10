//! Binding adapters to ports. The one place a concrete adapter is named.

use heyl_app::{AppError, Ports, recovery::CodeSource};
use heyl_grpc::{DomainApi, GrpcClient, GrpcConfig};
use heyl_platform::{HeadlessSecretStore, KeyringStore, OsRandom, SystemClock, SystemTerminal};
use heyl_ports::SecretStore;
use zeroize::Zeroizing;

/// Every adapter, owned. `heyl-app` borrows them through [`Ports`].
pub struct Adapters {
    api: DomainApi<GrpcClient>,
    store: Box<dyn SecretStore>,
    terminal: SystemTerminal,
    clock: SystemClock,
    random: OsRandom,

    /// The keychain and draw sequence a scenario supplied, when one did.
    ///
    /// One object serves both ports because they are chosen together: a run
    /// with a scenario's store but the OS random source would fail deep inside
    /// a decryption, for a reason that looks nothing like the cause.
    #[cfg(feature = "test-ports")]
    scenario: Option<heyl_platform::TestState>,
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
        // Service (DESIGN.md §5). The scenario suite is a third swap of the
        // same kind — see `ports`.
        let store: Box<dyn SecretStore> = if HeadlessSecretStore::is_configured() {
            Box::new(HeadlessSecretStore)
        } else {
            Box::new(KeyringStore)
        };

        // The domain port over the raw API, rather than the transport
        // implementing both. `heyl-app` still sees only `HeylApi`; what changed
        // is that the mapping and the token now sit in a layer that can be
        // pointed at something other than a socket (DESIGN.md §4).
        let context = config.context();
        Ok(Self {
            api: DomainApi::new(GrpcClient::new(config)?, context),
            store,
            terminal: SystemTerminal,
            clock: SystemClock,
            random: OsRandom,

            // Present only in a build made with `--features test-ports`, which
            // is what keeps a writable on-disk credential store out of every
            // binary a user can get (DESIGN.md §3).
            #[cfg(feature = "test-ports")]
            scenario: heyl_platform::TestState::from_env()
                .map_err(|reason| AppError::Api(heyl_ports::ApiError::Transport { reason }))?,
        })
    }

    /// Borrow them as the core expects.
    pub fn ports(&self) -> Ports<'_> {
        #[cfg(feature = "test-ports")]
        if let Some(scenario) = &self.scenario {
            return Ports {
                api: &self.api,
                store: scenario,
                terminal: &self.terminal,
                clock: &self.clock,
                // A recording binds the store but keeps the OS random source,
                // so `rekey` has real material to substitute.
                random: if scenario.drives_randomness() {
                    scenario
                } else {
                    &self.random
                },
            };
        }

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
