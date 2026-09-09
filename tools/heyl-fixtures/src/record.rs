//! Recording a whole session, at the API boundary.
//!
//! `heyl-grpc` generates the `RecordingApi` decorator — 123 forwarding methods
//! that keep what crossed — because a trait that wide has no hand-written
//! generic implementation. What lands on disk is prost messages as
//! protobuf-JSON, not gRPC-Web frames: a record is then something the whole
//! stack above the transport can replay, and re-keying it is rewriting fields
//! rather than decoding and re-encoding a body (DESIGN.md §6).
//!
//! **One pass.** A recording is made during a real, destructive recovery, and
//! that opportunity does not repeat without pairing a phone again. So this runs
//! the product's own path — `heyl recovery` then `heyl doctor` through
//! `heyl-app` — rather than a hand-rolled sequence of the same calls, and
//! captures every exchange of a whole session in order.
//!
//! The output holds **real key material and a live token**. It is input to
//! `rekey`, never something to commit.

use std::path::Path;

pub async fn run(endpoint: &str, out: &Path, confirm: bool) -> Result<(), String> {
    let email = std::env::var("HEYL_EMAIL")
        .map_err(|_| "set HEYL_EMAIL (try running under `secrets-env`)".to_owned())?;
    let code = std::env::var("HEYL_RECOVERY_CODE")
        .map_err(|_| "set HEYL_RECOVERY_CODE (try running under `secrets-env`)".to_owned())?;

    let config = heyl_grpc::GrpcConfig {
        endpoint: endpoint.to_owned(),
        ..heyl_grpc::GrpcConfig::default()
    };
    let context = config.context();
    // Three layers, each doing one thing: `heyl-app` sees `HeylApi`, the
    // mapping happens in `DomainApi`, and the recorder sits between that and
    // the transport — so what is kept is the messages heylogin actually sent.
    let api = heyl_grpc::DomainApi::new(
        heyl_grpc::RecordingApi::new(
            heyl_grpc::GrpcClient::new(config).map_err(|e| format!("client: {e}"))?,
        ),
        context,
    );

    // --- the recovery itself, through heyl-app so the recording is of the
    //     path the product actually takes.
    let store = crate::mem::MemoryStore::default();
    let terminal = crate::mem::AnsweringTerminal::new(confirm);
    let clock = heyl_platform::SystemClock;
    let random = heyl_platform::OsRandom;
    let ports = heyl_app::Ports {
        api: &api,
        store: &store,
        terminal: &terminal,
        clock: &clock,
        random: &random,
    };

    let outcome = heyl_app::recovery::run(
        &ports,
        &email,
        if confirm {
            heyl_app::recovery::Confirmation::Granted
        } else {
            heyl_app::recovery::Confirmation::Ask("Disconnect and recover? [y/N] ")
        },
        heyl_app::recovery::CodeSource::Given(zeroize::Zeroizing::new(code)),
        heyl_domain::ChallengeEncoding::Utf8,
        heyl_domain::SessionType::BackupCode,
    )
    .await
    .map_err(|e| format!("recovery: {e}"))?;

    eprintln!(
        "recovered {}; session {}",
        outcome.user_id, outcome.session_id
    );
    if outcome.disconnected.is_empty() {
        eprintln!("nothing was disconnected (the account had no other authenticator)");
    } else {
        for d in &outcome.disconnected {
            eprintln!("disconnected {:?}  {}", d.kind, d.id);
        }
    }

    // --- then `doctor` itself, rather than a hand-rolled sequence of the same
    //     calls. It reads the stored token, sets it on the client, syncs,
    //     handles a token refresh, lists authenticators and walks every vault —
    //     so the recording is the product's own call sequence, in the order a
    //     wire-level replay will assert.
    let report = heyl_app::doctor::run(&ports)
        .await
        .map_err(|e| format!("doctor: {e}"))?;
    let (pass, fail, skip) = report.tally();
    eprintln!("doctor over the recorded session: {pass} passed, {fail} failed, {skip} skipped");
    if report.has_failures() {
        return Err(
            "doctor failed against the live account; the recording would bake in a \
                    broken session"
                .to_owned(),
        );
    }

    let records = api.inner().records();
    for (index, record) in records.iter().enumerate() {
        let path = heyl_grpc::corpus::write(out, index, record).map_err(|e| e.to_string())?;
        eprintln!("  {}", path.display());
    }
    eprintln!("\nwrote {} records to {}", records.len(), out.display());
    eprintln!(
        "This recording contains REAL key material and a live token. It is input to \
         `rekey`, which\nreplaces all of it with synthetic material; it must not be \
         committed as it stands."
    );
    Ok(())
}
