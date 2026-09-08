#!/usr/bin/env python3
"""Recover heylogin's protobuf schema from the published browser extension.

Regenerates proto/ and descriptors/heylogin.binpb, and proves the result lossless.

    python3 -m venv .venv && ./.venv/bin/pip install protobuf grpcio-tools
    ./.venv/bin/python tools/extract-protos.py all

STAGES  (each runs on its own; `all` runs them in order)

    fetch        download the current .xpi from addons.mozilla.org  -> .work/heylogin.xpi
    unpack       recover original TypeScript from .js.map           -> .work/src-recovered/
    descriptors  *_pb.ts -> FileDescriptorSet                       -> descriptors/heylogin.binpb
    render       FileDescriptorSet -> .proto source                 -> proto/
    verify       recompile and diff against the originals           -> exit 0 / 1

  --work, --proto-out and --descriptors-out override the paths.

WHY THIS WORKS

  The extension ships .js.map source maps with `sourcesContent`. In the recovered
  backend/backend-client-web/src/espb/*_pb.ts files, protoc-gen-es v2 embeds each
  FileDescriptorProto as base64:

      export const file_account_service: GenFile =
        fileDesc("ChVhY2NvdW50X3NlcnZpY2UucHJvdG8...", [file_achievements, ...]);

  THE CATCH: protoc-gen-es *strips* FileDescriptorProto.dependency and passes the imports as
  fileDesc()'s second argument instead. The `descriptors` stage rebuilds that list by mapping
  those file_* consts back to filenames -- locals from each file's own descriptor, well-known
  types via the file_google_protobuf_* convention. Skip it and the descriptors look complete
  but will not compile.

VERIFICATION

  `verify` recompiles the rendered .proto with protoc and compares the resulting
  FileDescriptorProtos against the originals recovered from the bundle, normalising only for
  what the generator does not embed:

      - source_code_info -- comments, stripped by the generator and unrecoverable
      - json_name where it equals the derived camelCase default

  Current status: all 53 files byte-identical. The three "unused import" warnings from protoc
  are faithful -- those imports are in the original schema.

SCOPE BOUNDARY

  .work/src-recovered/ (the recovered TypeScript) is a BUILD INPUT ONLY. It is gitignored,
  must never be committed, and must never be copied into the implementation. Only the derived
  artifacts are in-tree:

      proto/*.proto              the wire-format interface definition
      descriptors/heylogin.binpb the same thing as a FileDescriptorSet

  Implement against proto/ and HEYLOGIN_SPEC.md, never against the recovered source.
"""

from __future__ import annotations

import argparse
import base64
import difflib
import json
import pathlib
import re
import shutil
import importlib
import subprocess
import sys
import urllib.request
import zipfile

from google.protobuf import descriptor_pb2 as d
from google.protobuf import text_format
from google.protobuf.descriptor import FieldDescriptor as FD

AMO_API = "https://addons.mozilla.org/api/v5/addons/addon/heylogin/"
ESPB = "backend/backend-client-web/src/espb"
F = d.FieldDescriptorProto
SCALARS = {
    F.TYPE_DOUBLE: "double", F.TYPE_FLOAT: "float", F.TYPE_INT64: "int64",
    F.TYPE_UINT64: "uint64", F.TYPE_INT32: "int32", F.TYPE_FIXED64: "fixed64",
    F.TYPE_FIXED32: "fixed32", F.TYPE_BOOL: "bool", F.TYPE_STRING: "string",
    F.TYPE_BYTES: "bytes", F.TYPE_UINT32: "uint32", F.TYPE_SFIXED32: "sfixed32",
    F.TYPE_SFIXED64: "sfixed64", F.TYPE_SINT32: "sint32", F.TYPE_SINT64: "sint64",
}


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


# --------------------------------------------------------------------------- fetch
def stage_fetch(work: pathlib.Path) -> pathlib.Path:
    work.mkdir(parents=True, exist_ok=True)
    xpi = work / "heylogin.xpi"
    with urllib.request.urlopen(AMO_API, timeout=60) as r:
        meta = json.load(r)
    url = meta["current_version"]["file"]["url"]
    version = meta["current_version"]["version"]
    log(f"fetch: heylogin {version}\n       {url}")
    with urllib.request.urlopen(url, timeout=300) as r, xpi.open("wb") as f:
        shutil.copyfileobj(r, f)
    (work / "VERSION").write_text(version + "\n")
    log(f"fetch: {xpi} ({xpi.stat().st_size:,} bytes)")
    return xpi


# -------------------------------------------------------------------------- unpack
def stage_unpack(work: pathlib.Path) -> pathlib.Path:
    xpi, ext, src = work / "heylogin.xpi", work / "ext", work / "src-recovered"
    if not xpi.exists():
        sys.exit(f"missing {xpi} — run `fetch` first")
    shutil.rmtree(ext, ignore_errors=True)
    shutil.rmtree(src, ignore_errors=True)
    with zipfile.ZipFile(xpi) as z:
        z.extractall(ext)

    written = 0
    for m in ext.rglob("*.map"):
        try:
            data = json.loads(m.read_text())
        except (ValueError, UnicodeDecodeError):
            log(f"unpack: skipping unreadable map {m.name}")
            continue
        for name, content in zip(data.get("sources") or [], data.get("sourcesContent") or []):
            if content is None:
                continue
            rel = re.sub(r"^webpack://[^/]*/", "", re.sub(r"^(\.\./)+", "", name.replace("\x00", ""))).lstrip("/")
            if not rel or ".." in rel.split("/"):
                continue
            out = src / rel
            if out.exists():
                continue
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(content)
            written += 1
    log(f"unpack: recovered {written} source files -> {src}")
    return src


# --------------------------------------------------------------------- descriptors
CALL = re.compile(r'fileDesc\(\s*((?:"(?:[^"\\]|\\.)*"\s*\+?\s*)+)\s*(?:,\s*\[([^\]]*)\])?\s*\)', re.S)
STR = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _wkt_descriptor(path: str) -> d.FileDescriptorProto:
    """The protobuf runtime's own FileDescriptorProto for a well-known type."""
    mod = importlib.import_module("google.protobuf." + pathlib.PurePosixPath(path).stem + "_pb2")
    fd = d.FileDescriptorProto()
    fd.ParseFromString(mod.DESCRIPTOR.serialized_pb)
    return fd


def stage_descriptors(work: pathlib.Path, out: pathlib.Path) -> pathlib.Path:
    """protoc-gen-es strips FileDescriptorProto.dependency and passes the imported GenFile
    consts as fileDesc()'s 2nd argument instead. Rebuilding that list is essential: without it
    the descriptors look complete and will not compile."""
    espb = work / "src-recovered" / ESPB
    if not espb.is_dir():
        sys.exit(f"missing {espb} — run `unpack` first")

    const2file: dict[str, str] = {}
    raw_by_file: dict[str, bytes] = {}
    deps_by_file: dict[str, list[str]] = {}

    for f in sorted(espb.glob("*_pb.ts")):
        txt = f.read_text()
        const = re.search(r"export const (file_\w+)\s*:\s*GenFile", txt)
        call = CALL.search(txt)
        if not (const and call):
            log(f"descriptors: skipping {f.name} (no fileDesc)")
            continue
        b64 = "".join(STR.findall(call.group(1)))
        raw = base64.b64decode(b64 + "=" * (-len(b64) % 4))
        fd = d.FileDescriptorProto()
        fd.ParseFromString(raw)
        const2file[const.group(1)] = fd.name
        raw_by_file[fd.name] = raw
        deps_by_file[fd.name] = [x.strip() for x in (call.group(2) or "").split(",") if x.strip()]

    def resolve(const: str) -> str:
        if const in const2file:
            return const2file[const]
        if const.startswith("file_google_protobuf_"):
            return "google/protobuf/" + const[len("file_google_protobuf_"):] + ".proto"
        sys.exit(f"unresolved dependency const: {const}")

    own, wkt = [], set()
    for name in sorted(raw_by_file):
        fd = d.FileDescriptorProto()
        fd.ParseFromString(raw_by_file[name])
        assert not fd.dependency, f"{name} unexpectedly already carries dependencies"
        for c in deps_by_file[name]:
            r = resolve(c)
            fd.dependency.append(r)
            if r.startswith("google/protobuf/"):
                wkt.add(r)
        own.append(fd)

    # Naming the well-known types is not enough: a descriptor set that declares
    # google/protobuf/timestamp.proto as a dependency but does not contain it is exactly
    # what `protoc --include_imports` exists to prevent. Rust codegen (buffa via
    # connectrpc-build, prost via tonic-prost-build) resolves types from the set alone and
    # fails on the first unresolved name -- ".google.protobuf.Timestamp not found". Embed
    # the runtime's own copies, ahead of the files that import them.
    fds = d.FileDescriptorSet()
    for path in sorted(wkt):
        fds.file.append(_wkt_descriptor(path))
    fds.file.extend(own)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(fds.SerializeToString())
    log(f"descriptors: {len(own)} files, {sum(len(f.dependency) for f in own)} deps recovered, "
        f"+{len(wkt)} embedded well-known types {sorted(wkt)} -> {out}")
    return out


# -------------------------------------------------------------------------- render
def _json_name(n: str) -> str:
    out, up = [], False
    for c in n:
        if c == "_":
            up = True
        else:
            out.append(c.upper() if up else c)
            up = False
    return "".join(out)


def _rel(name: str, pkg: str) -> str:
    n = name.lstrip(".")
    return n[len(pkg) + 1:] if pkg and n.startswith(pkg + ".") else n


def _opt_value(fdesc, val):
    if fdesc.type == FD.TYPE_STRING:
        return '"%s"' % val.replace("\\", "\\\\").replace('"', '\\"')
    if fdesc.type == FD.TYPE_BOOL:
        return "true" if val else "false"
    if fdesc.type == FD.TYPE_ENUM:
        return fdesc.enum_type.values_by_number[val].name
    return str(val)


class _P:
    def __init__(self):
        self.buf, self.ind = [], 0

    def w(self, s=""):
        self.buf.append(("  " * self.ind + s).rstrip())

    def __str__(self):
        return "\n".join(self.buf) + "\n"


def _typename(f, pkg, maps):
    if f.type in (F.TYPE_MESSAGE, F.TYPE_ENUM, F.TYPE_GROUP):
        return _rel(f.type_name, pkg)
    return SCALARS[f.type]


def _field(p, f, pkg, maps):
    parts = []
    if f.type_name and f.type_name in maps:
        k, v = maps[f.type_name]
        parts.append(f"map<{_typename(k, pkg, maps)}, {_typename(v, pkg, maps)}>")
    else:
        if f.label == F.LABEL_REPEATED:
            parts.append("repeated")
        elif f.label == F.LABEL_REQUIRED:
            parts.append("required")
        elif getattr(f, "proto3_optional", False):
            parts.append("optional")
        parts.append(_typename(f, pkg, maps))
    parts += [f.name, "=", str(f.number)]
    opts = []
    if f.json_name and f.json_name != _json_name(f.name):
        opts.append(f'json_name = "{f.json_name}"')
    if f.HasField("default_value"):
        opts.append(f"default = {f.default_value}")
    if f.options.deprecated:
        opts.append("deprecated = true")
    if f.options.HasField("packed"):
        opts.append(f"packed = {str(f.options.packed).lower()}")
    p.w(" ".join(parts) + (" [" + ", ".join(opts) + "]" if opts else "") + ";")


def _enum(p, e):
    p.w(f"enum {e.name} {{")
    p.ind += 1
    if e.options.allow_alias:
        p.w("option allow_alias = true;")
    for v in e.value:
        p.w(f"{v.name} = {v.number}{' [deprecated = true]' if v.options.deprecated else ''};")
    for r in e.reserved_range:
        p.w(f"reserved {r.start}{'' if r.start == r.end else f' to {r.end}'};")
    for n in e.reserved_name:
        p.w(f'reserved "{n}";')
    p.ind -= 1
    p.w("}")


def _collect_maps(msg, prefix, out):
    for n in msg.nested_type:
        full = f"{prefix}.{n.name}"
        if n.options.map_entry:
            out[full] = (n.field[0], n.field[1])
        _collect_maps(n, full, out)


def _message(p, m, pkg, maps, prefix):
    p.w(f"message {m.name} {{")
    p.ind += 1
    for n in m.nested_type:
        if n.options.map_entry:
            continue
        _message(p, n, pkg, maps, f"{prefix}.{n.name}")
        p.w()
    for e in m.enum_type:
        _enum(p, e)
        p.w()
    synthetic = {f.oneof_index for f in m.field
                 if getattr(f, "proto3_optional", False) and f.HasField("oneof_index")}
    for f in m.field:
        if not f.HasField("oneof_index") or f.oneof_index in synthetic:
            _field(p, f, pkg, maps)
    for i, o in enumerate(m.oneof_decl):
        if i in synthetic:
            continue
        p.w()
        p.w(f"oneof {o.name} {{")
        p.ind += 1
        for f in m.field:
            if f.HasField("oneof_index") and f.oneof_index == i and not getattr(f, "proto3_optional", False):
                _field(p, f, pkg, maps)
        p.ind -= 1
        p.w("}")
    for r in m.reserved_range:
        end = "max" if r.end >= 536870911 else str(r.end - 1)
        p.w(f"reserved {r.start}{'' if str(r.start) == end else f' to {end}'};")
    for n in m.reserved_name:
        p.w(f'reserved "{n}";')
    p.ind -= 1
    p.w("}")


def _service(p, s, pkg):
    p.w(f"service {s.name} {{")
    p.ind += 1
    for m in s.method:
        i = ("stream " if m.client_streaming else "") + _rel(m.input_type, pkg)
        o = ("stream " if m.server_streaming else "") + _rel(m.output_type, pkg)
        body = " { option deprecated = true; }" if m.options.deprecated else " {}"
        p.w(f"rpc {m.name}({i}) returns ({o}){body}")
    p.ind -= 1
    p.w("}")


def _render(fd) -> str:
    pkg, maps = fd.package, {}
    for m in fd.message_type:
        _collect_maps(m, f".{pkg}.{m.name}" if pkg else f".{m.name}", maps)
    p = _P()
    p.w(f'syntax = "{fd.syntax or "proto2"}";')
    p.w()
    if pkg:
        p.w(f"package {pkg};")
        p.w()
    if fd.dependency:
        for dep in fd.dependency:
            p.w(f'import "{dep}";')
        p.w()
    emitted = False
    for fdesc, val in sorted(fd.options.ListFields(), key=lambda kv: kv[0].number):
        p.w(f"option {fdesc.name} = {_opt_value(fdesc, val)};")
        emitted = True
    if emitted:
        p.w()
    for e in fd.enum_type:
        _enum(p, e)
        p.w()
    for m in fd.message_type:
        _message(p, m, pkg, maps, f".{pkg}.{m.name}" if pkg else f".{m.name}")
        p.w()
    for s in fd.service:
        _service(p, s, pkg)
        p.w()
    return str(p)


def stage_render(binpb: pathlib.Path, out: pathlib.Path) -> pathlib.Path:
    fds = d.FileDescriptorSet()
    fds.ParseFromString(binpb.read_bytes())
    out.mkdir(parents=True, exist_ok=True)
    for old in out.glob("*.proto"):
        old.unlink()
    # The set embeds the well-known types so codegen can resolve them (see stage_descriptors),
    # but they are protoc's files, not heylogin's -- rendering them would put a second copy of
    # timestamp.proto on protoc's include path during `verify`.
    rendered = [fd for fd in fds.file if not fd.name.startswith("google/protobuf/")]
    for fd in rendered:
        f = out / fd.name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(_render(fd))
    log(f"render: {len(rendered)} .proto files -> {out}")
    return out


# -------------------------------------------------------------------------- verify
def _norm_msg(m):
    for f in m.field:
        if f.json_name == _json_name(f.name):
            f.ClearField("json_name")
    for n in m.nested_type:
        _norm_msg(n)


def _norm(f):
    f.ClearField("source_code_info")
    for m in f.message_type:
        _norm_msg(m)
    return f


def stage_verify(work: pathlib.Path, binpb: pathlib.Path, proto: pathlib.Path) -> bool:
    """Recompile the rendered .proto and diff descriptors against the recovered originals,
    normalising only for what protoc-gen-es does not embed: source_code_info (comments) and
    json_name where it equals the derived default."""
    import grpc_tools.protoc as gp
    wkt = pathlib.Path(gp.__file__).parent / "_proto"
    roundtrip = work / "roundtrip.binpb"
    names = sorted(p.name for p in proto.glob("*.proto"))
    rc = gp.main(["protoc", f"-I{proto}", f"-I{wkt}", "--include_imports",
                  f"--descriptor_set_out={roundtrip}", *names])
    if rc != 0 or not roundtrip.exists():
        sys.exit("verify: protoc failed")

    def load(p):
        s = d.FileDescriptorSet()
        s.ParseFromString(p.read_bytes())
        return {f.name: f for f in s.file}

    skip = lambda k: k.startswith("google/protobuf/")
    orig = {k: v for k, v in load(binpb).items() if not skip(k)}
    rt = {k: v for k, v in load(roundtrip).items() if not skip(k)}
    bad = 0
    if set(orig) != set(rt):
        log(f"verify: FILE SET MISMATCH {set(orig) ^ set(rt)}")
        bad += 1
    for name in sorted(set(orig) & set(rt)):
        a, b = _norm(orig[name]), _norm(rt[name])
        if a.SerializeToString(deterministic=True) != b.SerializeToString(deterministic=True):
            bad += 1
            diff = difflib.unified_diff(
                text_format.MessageToString(a).splitlines(),
                text_format.MessageToString(b).splitlines(),
                f"recovered/{name}", f"roundtrip/{name}", lineterm="", n=1)
            log("\n".join(list(diff)[:40]))
    if bad:
        log(f"verify: {bad} FILES DIFFER")
        return False
    log(f"verify: ALL {len(orig)} FILES IDENTICAL")
    return True


# ---------------------------------------------------------------------------- main
def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("stage", choices=["fetch", "unpack", "descriptors", "render", "verify", "all"])
    ap.add_argument("--work", type=pathlib.Path, default=pathlib.Path(".work"),
                    help="scratch directory for the .xpi and recovered sources (default: .work)")
    ap.add_argument("--descriptors-out", type=pathlib.Path, default=root / "descriptors/heylogin.binpb")
    ap.add_argument("--proto-out", type=pathlib.Path, default=root / "proto")
    a = ap.parse_args()

    s = a.stage
    if s in ("fetch", "all"):
        stage_fetch(a.work)
    if s in ("unpack", "all"):
        stage_unpack(a.work)
    if s in ("descriptors", "all"):
        stage_descriptors(a.work, a.descriptors_out)
    if s in ("render", "all"):
        stage_render(a.descriptors_out, a.proto_out)
    if s in ("verify", "all"):
        if not stage_verify(a.work, a.descriptors_out, a.proto_out):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
