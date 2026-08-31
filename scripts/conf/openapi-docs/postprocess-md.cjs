#!/usr/bin/env node
// Post-process the Markdown produced by oas-to-markdown (api:md).
//
// 1. Pipe-free union labels
//
//    oas-to-markdown 0.1.0 double-escapes the "|" separator in "one of: ..."
//    type labels: schemaTypeLabel() joins the branches with " \| " and
//    tableCell() escapes the pipe again, so the file contains "\\|". In a GFM
//    table "\\|" renders as a literal backslash followed by a real column
//    separator, which breaks the row: the type cell is cut at
//    "one of: null \" and the link lands in the next column.
//
//    Until upstream ships a fix, rewrite the two-branch null-union labels to
//    the plain referenced type:
//
//      `one of: null \\| [Role](#role)`  ->  `[Role](#role)`
//
// 2. Drop ", nullable" type suffixes
//
//    The Type column marks optional fields with a ", nullable" suffix
//    ("string, nullable", "integer, nullable(int64)", ...). The Required
//    column already states optionality, so the suffix is noise for readers:
//    an optional field is documented by the type it takes when present.
//    Strip the suffix so the Type column shows just that type.
//
// The script fails loudly if any double-escaped pipe survives, so a change in
// the generator output cannot pass silently.

"use strict";

const fs = require("fs");

const target = process.argv[2];
if (!target) {
  console.error("usage: node postprocess-md.cjs <markdown-file>");
  process.exit(2);
}

let text = fs.readFileSync(target, "utf8");

// --- 1. null-union labels -> plain referenced type -------------------------
// Match the double-escaped separator emitted by oas-to-markdown 0.1.0, then
// (for forward compatibility) the single-escaped form a fixed upstream would
// emit.
text = text.replace(/one of: null \\\\\| (\[[^\]]+\]\([^)\s]*\))/g, "$1");
text = text.replace(/one of: null \\\| (\[[^\]]+\]\([^)\s]*\))/g, "$1");

// Any other union label keeps its meaning but must not keep a broken
// separator: fall back to " or ".
text = text.replace(/ \\\\\| /g, " or ");

// --- 2. strip ", nullable" from type labels --------------------------------
// ", nullable" only ever appears at the end of a type label, followed by the
// cell-separating pipe (possibly after a space) or by a format suffix like
// "(int64)".
text = text.replace(/, nullable(?=\s*[|(])/g, "");

// --- sentinel --------------------------------------------------------------
if (text.includes("\\\\|")) {
  console.error(`postprocess-md: unexpected double-escaped pipe remains in ${target}`);
  process.exit(1);
}

fs.writeFileSync(target, text);
