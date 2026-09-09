//! Generate `HeyloginApi` — one method per RPC — from `descriptors/heylogin.binpb`.
//!
//! Three artifacts come out of one walk of the descriptor set, because a
//! 123-method trait admits no hand-written generic implementation: the trait
//! itself, its complete implementation over [`GrpcClient`], and the dispatch
//! table `heyl api` uses to turn a method name into a typed call. Writing any
//! of them by hand would mean 123 near-identical blocks that drift the moment
//! the schema moves (DESIGN.md §4).
//!
//! The walk goes through `prost_build::ServiceGenerator` rather than parsing
//! the `FileDescriptorSet` directly. That is the supported hook, and it hands
//! back `input_type` / `output_type` already resolved to Rust paths — so the
//! generated code cannot disagree with `heyl-proto` about what a message is
//! called, which hand-rolled name mangling eventually would.
//!
//! Method names are **always** qualified by service. `Update` appears on five
//! services, `List` on five, `Delete` on four: a flat trait over one package
//! collides. Qualifying only on collision would mean a method renames itself
//! when heylogin adds an RPC elsewhere, so every method carries its service.

use std::{
    env,
    fmt::Write as _,
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use prost::Message as _;
use prost_build::{Service, ServiceGenerator};
use prost_types::FileDescriptorSet;

/// Collects every service instead of emitting anything in place.
///
/// `prost_build` writes its own output per proto file; we want one file for
/// the whole schema, so the services are gathered here and rendered after the
/// walk finishes.
struct Collect(Arc<Mutex<Vec<Service>>>);

impl ServiceGenerator for Collect {
    fn generate(&mut self, service: Service, _buf: &mut String) {
        self.0.lock().expect("not poisoned").push(service);
    }
}

/// The trait method name for one RPC: service, minus its `Service` suffix,
/// then the method. `CredentialService.CreateTokens` → `credential_create_tokens`.
fn method_name(service: &Service, method: &prost_build::Method) -> String {
    let prefix = service
        .name
        .strip_suffix("Service")
        .unwrap_or(&service.name)
        .to_owned();
    format!("{}_{}", to_snake(&prefix), method.name)
}

/// `CredentialService` → `credential_service`. Only ever applied to the
/// already-Rust-cased service name, so this handles the acronym runs the
/// schema actually contains (`LFDOverrides`, `GWorkspace`).
fn to_snake(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let mut out = String::with_capacity(name.len() + 4);
    for (i, &c) in chars.iter().enumerate() {
        if c.is_uppercase() {
            let starts_word = i > 0
                && (!chars[i - 1].is_uppercase()
                    || chars.get(i + 1).is_some_and(|n| n.is_lowercase()));
            if starts_word {
                out.push('_');
            }
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// The gRPC path a call goes to, e.g. `/domain.SyncService/Sync`.
fn path(service: &Service, method: &prost_build::Method) -> String {
    format!(
        "/{}.{}/{}",
        service.package, service.proto_name, method.proto_name
    )
}

/// What one walk of the schema produces.
#[derive(Default)]
struct Rendered {
    /// Trait method declarations, with their default bodies.
    trait_methods: String,
    /// The implementation over `GrpcClient`.
    impls: String,
    /// The `heyl api` dispatch arms, unary only.
    dispatch: String,
    /// Every RPC's path and method name.
    catalogue: String,
    /// How many methods were emitted.
    count: usize,
}

/// Render every service into the four buffers.
fn render(services: &[Service]) -> Rendered {
    let mut out = Rendered::default();
    for service in services {
        for method in &service.methods {
            out.count += 1;
            render_method(&mut out, service, method);
        }
    }
    out
}

/// Render one RPC: a trait method, its implementation, a catalogue entry, and —
/// for a unary method — a dispatch arm.
fn render_method(out: &mut Rendered, service: &Service, method: &prost_build::Method) {
    let name = method_name(service, method);
    let path = path(service, method);
    let input = format!("heyl_proto::{}", method.input_type);
    let output = format!("heyl_proto::{}", method.output_type);

    // Client-streaming would need a different signature; the schema has none,
    // so it is a hard error rather than a silent omission.
    assert!(
        !method.client_streaming,
        "{path} is client-streaming; the generator models unary and server-streaming only"
    );

    let (ret, call) = if method.server_streaming {
        (
            format!("crate::MessageStream<{output}>"),
            format!("self.server_streaming(request, {path:?}).await"),
        )
    } else {
        (output, format!("self.unary(request, {path:?}).await"))
    };

    let _ = write!(
        out.trait_methods,
        "    /// `{path}`\n    ///\n    /// # Errors\n    /// [`ApiError`] on any transport or backend failure.\n\
         \x20   async fn {name}(&self, request: crate::Request<{input}>) -> Result<{ret}, ApiError> {{\n\
         \x20       let _ = request;\n\
         \x20       Err(ApiError::Unimplemented {{ method: {path:?} }})\n\
         \x20   }}\n\n"
    );

    let _ = write!(
        out.impls,
        "    async fn {name}(&self, request: crate::Request<{input}>) -> Result<{ret}, ApiError> {{\n\
         \x20       {call}\n\
         \x20   }}\n\n"
    );

    let _ = writeln!(out.catalogue, "    ({path:?}, {name:?}),");

    // Only unary methods are reachable through the JSON dispatch: a stream has
    // no single response document to print, and the CLI renders it as NDJSON
    // through its own path.
    if !method.server_streaming {
        let _ = write!(
            out.dispatch,
            "        {path:?} => {{\n\
             \x20           let message: {input} = crate::json::from_json(pool, {:?}, body)?;\n\
             \x20           let response = api.{name}(context.request(message)).await?;\n\
             \x20           Ok(crate::json::to_json(pool, {:?}, &response)?)\n\
             \x20       }}\n",
            method.input_proto_type.trim_start_matches('.'),
            method.output_proto_type.trim_start_matches('.'),
        );
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let descriptors = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../descriptors/heylogin.binpb")
        .canonicalize()?;
    println!("cargo:rerun-if-changed={}", descriptors.display());
    println!("cargo:rerun-if-changed=build.rs");

    let out: PathBuf = env::var("OUT_DIR")?.into();
    let fds = FileDescriptorSet::decode(&*fs::read(&descriptors)?)?;

    // `prost_build` insists on writing the message types too. They are
    // `heyl-proto`'s job, so they go to a scratch directory and are discarded;
    // what we keep is what the service generator collected.
    let scratch = out.join("discarded-messages");
    fs::create_dir_all(&scratch)?;

    let services = Arc::new(Mutex::new(Vec::new()));
    prost_build::Config::new()
        .out_dir(&scratch)
        .service_generator(Box::new(Collect(Arc::clone(&services))))
        .compile_fds(fds)?;

    let services = services.lock().expect("not poisoned");
    let Rendered {
        trait_methods,
        impls,
        dispatch,
        catalogue,
        count,
    } = render(&services);

    let generated = format!(
        "// @generated by heyl-grpc/build.rs from descriptors/heylogin.binpb.\n\
         // {count} methods across {} services. Do not edit.\n\n\
         /// heylogin's gRPC surface, one method per RPC.\n\
         ///\n\
         /// Every method defaults to [`ApiError::Unimplemented`] naming its own\n\
         /// path, so a stub overrides only what it exercises. [`GrpcClient`]\n\
         /// overrides all of them.\n\
         #[async_trait::async_trait]\n\
         pub trait HeyloginApi: Send + Sync {{\n{trait_methods}}}\n\n\
         #[async_trait::async_trait]\n\
         impl<T> HeyloginApi for GrpcClient<T>\n\
         where\n\
         \x20   T: Transportable + Sync,\n\
         \x20   T::Future: Send,\n\
         {{\n{impls}}}\n\n\
         /// Every RPC in the schema: gRPC path, and the trait method serving it.\n\
         pub const METHODS: [(&str, &str); {count}] = [\n{catalogue}];\n",
        services.len(),
    );
    fs::write(out.join("api.rs"), generated)?;

    // The dispatch is only compiled under the `api` feature, so it is written
    // unconditionally and included conditionally.
    let dispatch = format!(
        "// @generated by heyl-grpc/build.rs. Do not edit.\n\n\
         /// Call one RPC by gRPC path, JSON in and JSON out.\n\
         ///\n\
         /// # Errors\n\
         /// [`DispatchError`] if the method is unknown, the body does not\n\
         /// parse, or the call fails.\n\
         pub async fn dispatch(\n\
         \x20   api: &dyn HeyloginApi,\n\
         \x20   context: &crate::ClientContext,\n\
         \x20   method: &str,\n\
         \x20   body: &str,\n\
         ) -> Result<String, crate::DispatchError> {{\n\
         \x20   let pool = crate::json::pool()?;\n\
         \x20   match method {{\n{dispatch}\
         \x20       other => Err(crate::DispatchError::UnknownMethod {{ method: other.to_owned() }}),\n\
         \x20   }}\n\
         }}\n"
    );
    fs::write(out.join("dispatch.rs"), dispatch)?;

    Ok(())
}
