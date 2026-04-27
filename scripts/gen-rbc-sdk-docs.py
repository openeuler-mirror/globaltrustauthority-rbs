#!/usr/bin/env python3
"""
Generate Markdown API reference from Rust source files.

Usage:
    python3 scripts/gen-rbc-sdk-docs.py [inputs ...] [--output PATH]

Arguments:
    inputs   One or more .rs files or directories (default: rbc/src/sdk.rs)
    --output Output markdown path (default: docs/api/rbc/sdk.md)

Examples:
    python3 scripts/gen-rbc-sdk-docs.py
    python3 scripts/gen-rbc-sdk-docs.py rbc/src/sdk.rs rbc/src/ffi/mod.rs --output docs/api/rbc/full.md
    python3 scripts/gen-rbc-sdk-docs.py rbc/src/ --output docs/api/rbc/full.md

How it works:
    The script scans Rust source files line by line and extracts:
      - `pub struct` — public structs with their `pub` fields and inherent-impl `pub fn` methods
      - `pub enum`   — public enums with their variants and inherent-impl `pub fn` methods
      - `///` doc comments immediately preceding each type, field, variant, or method

    The following are skipped:
      - `pub(crate)` / `pub(super)` and other restricted-visibility items
      - `impl Trait for Type` (trait impls); only inherent impls are processed
      - `#[cfg(test)]` blocks
      - Types whose name contains "Inner" or starts with "_" (treated as internal)
      - Top-level standalone `pub fn` (module-level functions are not extracted)

    Output order follows source order; with multiple input files types are appended
    in file order. Duplicate type names across files keep the first occurrence.
"""

import argparse
import re
import sys
from pathlib import Path


# ── helpers ───────────────────────────────────────────────────────────────────

def join_doc(lines):
    return " ".join(lines).strip()


def clean_sig(raw_lines):
    sig = " ".join(l.strip() for l in raw_lines)
    sig = re.sub(r"\s*\{.*", "", sig).strip()   # drop trailing `{`
    return re.sub(r"\s+", " ", sig)


def is_internal(name):
    return "Inner" in name or name.startswith("_")


def collect_rs_files(inputs):
    seen = set()
    result = []
    for raw in inputs:
        p = Path(raw)
        if p.is_dir():
            candidates = sorted(p.rglob("*.rs"))
        else:
            candidates = [p]
        for f in candidates:
            if f not in seen:
                seen.add(f)
                result.append(f)
    if not result:
        sys.exit("error: no .rs files found in the given inputs")
    return result


# ── sub-parsers (index-based, return next index) ──────────────────────────────

def skip_cfg_test(lines, i):
    """Skip past the block that follows #[cfg(test)]."""
    j = i
    depth = 0
    started = False
    while j < len(lines):
        for ch in lines[j]:
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
        j += 1
        if started and depth == 0:
            break
    return j


def get_method_sig(lines, i):
    """Collect a complete `pub fn` signature. Returns (sig_str, next_i)."""
    parts = []
    paren_depth = 0
    j = i
    while j < len(lines):
        line = lines[j]
        parts.append(line)
        for ch in line:
            if ch == "(":
                paren_depth += 1
            elif ch == ")":
                paren_depth -= 1
        j += 1
        if paren_depth <= 0 and ("{" in line or line.strip().endswith(";")):
            break
    return clean_sig(parts), j


def skip_fn_body(lines, i):
    """Skip a function body `{ … }`. i should point to the first line after the `{`."""
    depth = 1
    j = i
    while j < len(lines) and depth > 0:
        for ch in lines[j]:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
        j += 1
    return j


def get_struct_fields(lines, i):
    """Parse public fields inside a struct body. Returns (fields, next_i)."""
    fields = []
    doc = []
    depth = 1
    j = i
    while j < len(lines):
        line = lines[j]
        s = line.strip()

        brace_net = line.count("{") - line.count("}")
        depth += brace_net
        j += 1

        if depth <= 0:
            break

        m = re.match(r"\s*///\s?(.*)", line)
        if m:
            doc.append(m.group(1))
            continue

        # public field: `pub name: Type,`
        m = re.match(r"^pub (\w+)\s*:\s*(.+?),?\s*$", s)
        if m and not s.startswith("pub(") and "fn " not in s[:10]:
            fields.append({
                "name": m.group(1),
                "type": m.group(2).rstrip(",").strip(),
                "docs": join_doc(doc),
            })
            doc = []
            continue

        if s and not s.startswith("#[") and not s.startswith("//"):
            doc = []

    return fields, j


def get_enum_variants(lines, i):
    """Parse variants inside an enum body. Returns (variants, next_i)."""
    variants = []
    doc = []
    depth = 1
    j = i
    while j < len(lines):
        line = lines[j]
        s = line.strip()

        brace_net = line.count("{") - line.count("}")
        depth += brace_net
        j += 1

        if depth <= 0:
            break

        m = re.match(r"\s*///\s?(.*)", line)
        if m:
            doc.append(m.group(1))
            continue

        # variant at depth 1 — name starts with uppercase
        m = re.match(r"^([A-Z]\w*)(.*)", s)
        if m and (depth - brace_net) == 1:   # was depth 1 before brace_net applied
            vname = m.group(1)
            payload = m.group(2).strip().rstrip(",").strip()
            variants.append({"name": vname, "payload": payload, "docs": join_doc(doc)})
            doc = []
            continue

        if s and not s.startswith("#[") and not s.startswith("//"):
            doc = []

    return variants, j


def get_impl_methods(lines, i):
    """Parse public methods inside an impl block. Returns (methods, next_i)."""
    methods = []
    doc = []
    depth = 1
    j = i
    while j < len(lines):
        line = lines[j]
        s = line.strip()

        m = re.match(r"\s*///\s?(.*)", line)
        if m:
            doc.append(m.group(1))
            j += 1
            continue

        if depth == 1 and re.match(r"\s+pub fn ", line) and not re.match(r"\s+pub\(", line):
            saved_doc = join_doc(doc)
            doc = []
            sig, j = get_method_sig(lines, j)
            name_m = re.search(r"pub fn (\w+)", sig)
            methods.append({
                "name": name_m.group(1) if name_m else "?",
                "sig": sig,
                "docs": saved_doc,
            })
            # skip method body
            j = skip_fn_body(lines, j)
            continue

        # update depth for non-method lines
        brace_net = line.count("{") - line.count("}")
        depth += brace_net
        j += 1

        if depth <= 0:
            break

        if s and not s.startswith("#[") and not s.startswith("//"):
            doc = []

    return methods, j


# ── main parser ───────────────────────────────────────────────────────────────

def parse(source):
    lines = source.splitlines()
    N = len(lines)
    result = {}
    doc = []
    i = 0

    while i < N:
        line = lines[i]
        s = line.strip()

        if s == "#[cfg(test)]":
            i = skip_cfg_test(lines, i + 1)
            doc = []
            continue

        m = re.match(r"^\s*///\s?(.*)", line)
        if m:
            doc.append(m.group(1))
            i += 1
            continue

        if not s:
            i += 1
            continue

        if s.startswith("#["):
            i += 1
            continue

        # pub struct TypeName
        m = re.match(r"^pub struct (\w+)", s)
        if m and not s.startswith("pub("):
            name = m.group(1)
            saved = join_doc(doc)
            doc = []
            i += 1
            fields, i = get_struct_fields(lines, i)
            result[name] = {"kind": "struct", "docs": saved, "fields": fields, "methods": []}
            continue

        # pub enum TypeName
        m = re.match(r"^pub enum (\w+)", s)
        if m and not s.startswith("pub("):
            name = m.group(1)
            saved = join_doc(doc)
            doc = []
            i += 1
            variants, i = get_enum_variants(lines, i)
            result[name] = {"kind": "enum", "docs": saved, "variants": variants, "methods": []}
            continue

        # impl TypeName  (skip trait impls)
        m = re.match(r"^impl(?:\s*<[^>]*>)?\s+(\w+)", s)
        if m and " for " not in s:
            type_name = m.group(1)
            doc = []
            i += 1
            if type_name in result:
                methods, i = get_impl_methods(lines, i)
                result[type_name]["methods"].extend(methods)
            else:
                # skip unknown impl (e.g. ClientInner)
                depth = 1
                while i < N and depth > 0:
                    depth += lines[i].count("{") - lines[i].count("}")
                    i += 1
            continue

        doc = []
        i += 1

    return result


def merge_parsed(files):
    """Parse each file and merge results, first-seen wins on name conflicts."""
    merged = {}
    for path in files:
        source = path.read_text()
        types = parse(source)
        for name, info in types.items():
            if name in merged:
                print(f"warning: duplicate type '{name}' in {path}, skipping")
            else:
                merged[name] = info
    return merged


# ── Markdown renderer ─────────────────────────────────────────────────────────

def render(types, sources):
    source_list = ", ".join(f"`{p}`" for p in sources)
    out = [
        "# RBC SDK Reference",
        "",
        f"> Generated from {source_list}.",
        "",
        "---",
        "",
    ]

    for name, t in types.items():
        if is_internal(name):
            continue

        out.append(f"## `{name}`")
        out.append("")
        if t["docs"]:
            out.append(t["docs"])
            out.append("")

        if t["kind"] == "struct":
            fields = [f for f in t.get("fields", []) if f["name"] != "_marker"]
            if fields:
                out.append("**Fields**")
                out.append("")
                out.append("| Field | Type | Description |")
                out.append("|-------|------|-------------|")
                for f in fields:
                    out.append(f"| `{f['name']}` | `{f['type']}` | {f['docs']} |")
                out.append("")

            methods = t.get("methods", [])
            if methods:
                out.append("**Methods**")
                out.append("")
                for m in methods:
                    out.append(f"#### `{m['name']}`")
                    out.append("")
                    out.append("```rust")
                    out.append(m["sig"])
                    out.append("```")
                    if m["docs"]:
                        out.append("")
                        out.append(m["docs"])
                    out.append("")

        elif t["kind"] == "enum":
            variants = t.get("variants", [])
            if variants:
                out.append("**Variants**")
                out.append("")
                for v in variants:
                    payload = v["payload"]
                    if payload:
                        sep = " " if payload.startswith("{") else ""
                        sig = f"`{v['name']}{sep}{payload}`"
                    else:
                        sig = f"`{v['name']}`"
                    doc_suffix = f" — {v['docs']}" if v["docs"] else ""
                    out.append(f"- {sig}{doc_suffix}")
                out.append("")

        out.append("---")
        out.append("")

    return "\n".join(out)


# ── entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Generate Markdown API reference from Rust source files."
    )
    parser.add_argument(
        "inputs",
        nargs="*",
        default=["rbc/src/sdk.rs"],
        metavar="INPUT",
        help=".rs files or directories to parse (default: rbc/src/sdk.rs)",
    )
    parser.add_argument(
        "--output",
        default="docs/api/rbc/sdk.md",
        metavar="PATH",
        help="output markdown path (default: docs/api/rbc/sdk.md)",
    )
    args = parser.parse_args()

    files = collect_rs_files(args.inputs)
    types = merge_parsed(files)
    md = render(types, files)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md)
    print(f"written: {out}  ({md.count(chr(10))} lines)")


if __name__ == "__main__":
    main()
