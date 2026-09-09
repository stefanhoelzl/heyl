//! The recorded session, replayed through the real adapter.
//!
//! This is the layer a port-level fake cannot reach. Both defects M2 shipped
//! lived here — the `ProfileAuthenticatorLock` mapping rule, and reading
//! `DomainError` from the wrong `tonic` API — and one of them passed green
//! because the test hand-built the `Status` the way the broken code read it.
//! Here the bytes are heylogin's own, so mapping, error decoding and gRPC-Web
//! framing are all under test.
//!
//! The fixture is a real session with every secret replaced (see
//! `tools/heyl-fixtures rekey`): real vault documents, synthetic keys. It opens
//! with the committed test code and with nothing else — which is what makes it
//! safe to commit, and what this test demonstrates by opening it.

use std::{
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use base64::Engine as _;

#[derive(serde::Deserialize)]
struct Exchange {
    path: String,
    response: String,
    headers: Vec<(String, String)>,
}

#[derive(serde::Deserialize)]
struct Meta {
    code: String,
    session_seed: String,
}

#[derive(serde::Deserialize)]
struct Fixture {
    meta: Meta,
    exchanges: Vec<Exchange>,
}

/// Answers from the fixture, in order.
#[derive(Clone)]
struct Replay {
    exchanges: Arc<Vec<Exchange>>,
    at: Arc<Mutex<usize>>,
}

/// The code and session seed the fixture was built with.
struct Keys {
    code: String,
    session_seed: [u8; 32],
}

impl Replay {
    fn load() -> (Self, Keys) {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/wire/session.json"
        ))
        .expect("the wire fixture is committed");
        let fixture: Fixture = serde_json::from_str(&raw).expect("fixture parses");
        let seed = base64::engine::general_purpose::STANDARD
            .decode(&fixture.meta.session_seed)
            .expect("fixture states its session seed");
        let keys = Keys {
            code: fixture.meta.code,
            session_seed: seed.try_into().expect("32 bytes"),
        };
        (
            Self {
                exchanges: Arc::new(fixture.exchanges),
                at: Arc::new(Mutex::new(0)),
            },
            keys,
        )
    }

    /// How many exchanges were consumed.
    fn consumed(&self) -> usize {
        *self.at.lock().expect("not poisoned")
    }
}

impl<ReqBody> tower::Service<http::Request<ReqBody>> for Replay {
    type Response = http::Response<http_body_util::Full<bytes::Bytes>>;
    type Error = std::convert::Infallible;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<ReqBody>) -> Self::Future {
        let path = req.uri().path().to_owned();
        let exchanges = Arc::clone(&self.exchanges);
        let at = Arc::clone(&self.at);

        Box::pin(async move {
            let mut index = at.lock().expect("not poisoned");
            let exchange = exchanges.get(*index).unwrap_or_else(|| {
                panic!("the client made more calls than the recording holds; next was {path}")
            });
            // Order is the contract. A changed call sequence must fail loudly
            // here rather than quietly decrypting the wrong vault later.
            assert_eq!(
                exchange.path, path,
                "call {} was {path}, but the recording has {}",
                *index, exchange.path
            );
            *index += 1;

            let body = base64::engine::general_purpose::STANDARD
                .decode(&exchange.response)
                .expect("recorded response is base64");
            let mut builder = http::Response::builder().status(200);
            for (k, v) in &exchange.headers {
                builder = builder.header(k, v);
            }
            Ok(builder
                .body(http_body_util::Full::new(bytes::Bytes::from(body)))
                .expect("a response the recording described"))
        })
    }
}

// ------------------------------------------------------------------ the ports

#[derive(Default)]
struct MemoryStore(Mutex<std::collections::HashMap<String, String>>);

#[async_trait::async_trait]
impl heyl_ports::SecretStore for MemoryStore {
    async fn get(
        &self,
        key: &heyl_ports::SecretKey,
    ) -> Result<zeroize::Zeroizing<String>, heyl_ports::PortError> {
        self.0
            .lock()
            .expect("not poisoned")
            .get(key.secret.name())
            .map(|v| zeroize::Zeroizing::new(v.clone()))
            .ok_or(heyl_ports::PortError::NotFound {
                what: key.secret.name(),
            })
    }
    async fn set(
        &self,
        key: &heyl_ports::SecretKey,
        value: &str,
    ) -> Result<(), heyl_ports::PortError> {
        self.0
            .lock()
            .expect("not poisoned")
            .insert(key.secret.name().to_owned(), value.to_owned());
        Ok(())
    }
    async fn delete(&self, _: &heyl_ports::SecretKey) -> Result<(), heyl_ports::PortError> {
        Ok(())
    }
}

struct SilentTerminal;

impl heyl_ports::Terminal for SilentTerminal {
    fn is_interactive(&self) -> bool {
        false
    }
    fn prompt_line(&self, _: &str) -> Result<String, heyl_ports::PortError> {
        unreachable!("the replay never prompts")
    }
    fn prompt_hidden(&self, _: &str) -> Result<zeroize::Zeroizing<String>, heyl_ports::PortError> {
        unreachable!("the replay never prompts")
    }
    fn read_line(&self) -> Result<zeroize::Zeroizing<String>, heyl_ports::PortError> {
        unreachable!("the replay never reads")
    }
    fn note(&self, _: &str) {}
}

struct FixedClock;

impl heyl_ports::Clock for FixedClock {
    fn now(&self) -> heyl_domain::Timestamp {
        heyl_domain::Timestamp::from_millisecond(1_757_376_000_000).expect("valid")
    }
    fn next_unlock_deadline(&self) -> heyl_domain::Timestamp {
        heyl_domain::Timestamp::from_millisecond(1_757_469_600_000).expect("valid")
    }
}

/// Yields the fixture's session seed first, then counts.
///
/// `recovery` derives its session key from the first draw, and the fixture's
/// unlock blob was sealed to exactly that key. Everything after it is a nonce
/// or an ephemeral key, where any value does.
struct FixtureRandom {
    session_seed: [u8; 32],
    drawn: Mutex<u8>,
}

impl FixtureRandom {
    fn new(session_seed: [u8; 32]) -> Self {
        Self {
            session_seed,
            drawn: Mutex::new(0),
        }
    }
}

impl heyl_ports::RandomSource for FixtureRandom {
    fn fill(&self, out: &mut [u8]) {
        let mut n = self.drawn.lock().expect("not poisoned");
        *n = n.wrapping_add(1);
        if *n == 1 && out.len() == 32 {
            out.copy_from_slice(&self.session_seed);
        } else {
            out.fill(*n);
        }
    }
}

// ------------------------------------------------------------------- the test

/// The whole M2 use case, over heylogin's own bytes.
///
/// Recovery through `heyl-app`, then `doctor` in the same process but through a
/// fresh set of calls, exactly as the recording was made. Every derivation link
/// and every vault must open — with the **committed test code**, which is the
/// property that makes the fixture safe to commit at all.
#[tokio::test]
async fn the_recorded_session_replays_through_the_real_adapter() {
    use tower::Layer as _;

    let (replay, keys) = Replay::load();
    let transport = tonic_web::GrpcWebClientLayer::new().layer(replay.clone());
    let api = heyl_grpc::GrpcClient::with_transport(heyl_grpc::GrpcConfig::default(), transport);

    let store = MemoryStore::default();
    let terminal = SilentTerminal;
    let clock = FixedClock;
    let random = FixtureRandom::new(keys.session_seed);
    let ports = heyl_app::Ports {
        api: &api,
        store: &store,
        terminal: &terminal,
        clock: &clock,
        random: &random,
    };

    let outcome = heyl_app::recovery::run(
        &ports,
        "fixture@example.com",
        heyl_app::recovery::Confirmation::Granted,
        // The synthetic code the fixture states it was re-keyed onto.
        heyl_app::recovery::CodeSource::Given(zeroize::Zeroizing::new(keys.code.clone())),
        heyl_domain::ChallengeEncoding::Utf8,
        heyl_domain::SessionType::BackupCode,
    )
    .await
    .expect("the fixture opens with the committed test code");

    // The recording was taken from a run that disconnected a phone, so the
    // shape a later recording could never reproduce is preserved here.
    assert_eq!(
        outcome.disconnected.len(),
        1,
        "the fixture should still show a push authenticator being disconnected"
    );
    assert_eq!(
        outcome.disconnected[0].kind,
        heyl_domain::AuthenticatorType::Push
    );

    let report = heyl_app::doctor::run(&ports).await.expect("doctor walks");
    let (pass, fail, skip) = report.tally();

    let failures: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.outcome == heyl_app::doctor::Outcome::Fail)
        .collect();
    assert!(failures.is_empty(), "unexpected failures: {failures:#?}");
    assert_eq!((fail, skip), (0, 0));
    assert!(pass >= 30, "expected the whole chain, got {pass} passes");

    assert_eq!(
        replay.consumed(),
        9,
        "every recorded exchange should have been used"
    );
}
