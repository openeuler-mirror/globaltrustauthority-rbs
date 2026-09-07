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
// 3. oneOf branch descriptions -> property table cells
//
//    utoipa 5 renders optional reference-typed fields (e.g. Option<Role>) as
//
//      { oneOf: [ {type: "null"}, { $ref: "...", description: "..." } ] }
//
//    so the field's doc comment lands as a $ref sibling INSIDE the oneOf
//    branch, not on the property. oas-to-markdown 0.1.0 only reads
//    property-level (or direct $ref sibling) descriptions, leaving those
//    table cells empty. Re-read the OpenAPI YAML and lift the branch
//    description into the empty cell of that property's table rows (both the
//    inline "Schema: [...]" tables and the schema reference sections).
//
// The script fails loudly on any anomaly, so a change in the generator output
// cannot pass silently.

"use strict";

const fs = require("fs");
const path = require("path");
const YAML = require("yaml");

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

// --- 3. oneOf branch descriptions -> property table cells -------------------
// utoipa's null-union properties carry the field doc comment as a $ref
// sibling inside the oneOf branch; oas-to-markdown 0.1.0 only reads
// property-level descriptions, so those cells stay empty. Fill them from the
// OpenAPI YAML: the MD lives at docs/api/rbs/md/, the YAML at docs/proto/.
const specPath = path.resolve(path.dirname(target), "..", "..", "..", "proto", "rbs_rest_api.yaml");
let spec;
try {
  spec = YAML.parse(fs.readFileSync(specPath, "utf8"));
} catch (e) {
  console.error(`postprocess-md: cannot read/parse OpenAPI spec ${specPath}: ${e.message}`);
  process.exit(1);
}

// schema-name -> property-name -> first line of the branch description
const oneOfDescriptions = new Map();
const schemas = spec?.components?.schemas ?? {};
for (const [schemaName, schema] of Object.entries(schemas)) {
  for (const [propName, prop] of Object.entries(schema?.properties ?? {})) {
    if (!Array.isArray(prop?.oneOf) || prop.description) continue;
    const branch = prop.oneOf.find(
      (b) => b && b.type !== "null" && typeof b.description === "string" && b.description.length > 0
    );
    if (!branch) continue;
    const first = String(branch.description).split(/\r?\n/)[0].trim();
    if (!first) continue;
    if (!oneOfDescriptions.has(schemaName)) oneOfDescriptions.set(schemaName, new Map());
    oneOfDescriptions.get(schemaName).set(propName, first.replace(/\|/g, "\\|"));
  }
}

// Walk the markdown keeping track of which schema a property table belongs
// to: either an inline "Schema: [Name](#anchor)" line or a "### Name"
// heading for a known component schema. Endpoint headings ("### GET /...")
// and parameter tables ("| Name | In | ...") never match, so they reset the
// context to null.
const PROP_TABLE_HEADER = "| Property | Type | Required | Description |";
const lines2 = text.split("\n");
let filled = 0;
let currentSchema = null;
const seenKeys = new Set();
for (let i = 0; i < lines2.length; i++) {
  const line = lines2[i];
  const schemaLink = line.match(/^Schema: \[([^\]]+)\]/);
  if (schemaLink) {
    currentSchema = schemaLink[1];
    continue;
  }
  const heading = line.match(/^### (.+)$/);
  if (heading) {
    // Schema reference sections carry a bare component name; endpoint
    // headings ("### GET /rbs/...") reset the context.
    const name = heading[1].trim();
    currentSchema = Object.prototype.hasOwnProperty.call(schemas, name) ? name : null;
    continue;
  }
  if (line !== PROP_TABLE_HEADER || currentSchema === null) continue;
  if (!oneOfDescriptions.has(currentSchema)) continue;
  const propDescs = oneOfDescriptions.get(currentSchema);
  // Fill rows of this table until a non-table line ends it.
  for (let j = i + 1; j < lines2.length; j++) {
    const row = lines2[j];
    if (!row.startsWith("|")) break; // table ended
    if (/^\|---/.test(row)) continue; // column separator row
    // ["", " `prop` ", " type ", " yes|no ", " description ", ""]
    const cells = row.split("|");
    if (cells.length !== 6) continue; // e.g. a row with escaped pipes
    const propName = cells[1].trim().replace(/^`|`$/g, "");
    if (!/^(yes|no)$/.test(cells[3].trim())) continue;
    if (cells[4].trim() === "" && propDescs.has(propName)) {
      cells[4] = ` ${propDescs.get(propName)} `;
      lines2[j] = cells.join("|");
      filled += 1;
    }
    if (propDescs.has(propName)) seenKeys.add(`${currentSchema}.${propName}`);
  }
}
if (oneOfDescriptions.size > 0) {
  const expected = [...oneOfDescriptions.entries()].flatMap(([s, props]) => [...props.keys()].map((p) => `${s}.${p}`));
  const missing = expected.filter((k) => !seenKeys.has(k));
  if (missing.length > 0) {
    console.error(`postprocess-md: oneOf-described properties missing from tables: ${missing.join(", ")} — generator layout changed?`);
    process.exit(1);
  }
}
text = lines2.join("\n");
console.log(`postprocess-md: ${filled} oneOf property description(s) filled`);

// --- sentinel --------------------------------------------------------------
if (text.includes("\\\\|")) {
  console.error(`postprocess-md: unexpected double-escaped pipe remains in ${target}`);
  process.exit(1);
}

fs.writeFileSync(target, text);
