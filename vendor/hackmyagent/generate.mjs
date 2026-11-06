// Prints one of the generated files under vendor/hackmyagent/, read from the
// published hackmyagent package:
//
//   check-ids.json        the sorted union of the keys of getTaxonomyMap() and the
//                         members of TAXONOMY_EXEMPT_CHECKIDS, from
//                         dist/hardening/taxonomy.js. The same bytes that
//                         aiis-signatures' vendor/hackmyagent/generate.mjs prints.
//   oasb-1-controls.json  every OASB-1 control id with its checkIds, from
//                         dist/benchmarks/oasb-1.js.
//   payload-ids.json      the sorted ids of ALL_PAYLOADS, from
//                         dist/attack/payloads/index.js.
//
// Usage:
//   npm pack hackmyagent@<version> --pack-destination <dir>
//   tar xzf <dir>/hackmyagent-<version>.tgz -C <dir>
//   env -i PATH="$PATH" node vendor/hackmyagent/generate.mjs <dir>/package check-ids.json > vendor/hackmyagent/check-ids.json
//
// The first argument is the extracted package directory (the one holding
// package.json); the second names the file to print. The script loads the
// package's own modules, so run it with an environment that holds PATH only.
// Output is stable: ids sorted, two space indent, trailing newline. Exit 2 on a
// usage error, 1 when the package does not have the expected shape.
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const USAGE =
  "usage: node generate.mjs <extracted hackmyagent package dir> " +
  "<check-ids.json|oasb-1-controls.json|payload-ids.json>";

const args = process.argv.slice(2);
const GENERATORS = {
  "check-ids.json": checkIds,
  "oasb-1-controls.json": oasbControls,
  "payload-ids.json": payloadIds,
};
if (args.length !== 2 || !Object.hasOwn(GENERATORS, args[1])) {
  console.error(USAGE);
  process.exit(2);
}
const [dir, name] = args;
const require = createRequire(import.meta.url);
const pkg = JSON.parse(readFileSync(resolve(dir, "package.json"), "utf8"));

function fail(message) {
  console.error(`generate.mjs: ${message}`);
  process.exit(1);
}

function checkIds() {
  const taxonomy = require(resolve(dir, "dist/hardening/taxonomy.js"));
  const ids = new Set(Object.keys(taxonomy.getTaxonomyMap()));
  for (const id of taxonomy.TAXONOMY_EXEMPT_CHECKIDS) ids.add(id);
  const sorted = [...ids].sort();
  return {
    package: pkg.name,
    version: pkg.version,
    count: sorted.length,
    checkIds: sorted,
  };
}

function oasbControls() {
  const oasb = require(resolve(dir, "dist/benchmarks/oasb-1.js"));
  const controls = [];
  const seen = new Set();
  for (const category of oasb.OASB_1_CATEGORIES) {
    for (const control of category.controls) {
      if (typeof control.id !== "string" || seen.has(control.id)) {
        fail(`OASB-1 control id ${JSON.stringify(control.id)} is missing or repeated`);
      }
      seen.add(control.id);
      const checks = control.checkIds ?? [];
      if (!Array.isArray(checks) || checks.some((id) => typeof id !== "string")) {
        fail(`OASB-1 control ${control.id} has checkIds that are not a list of strings`);
      }
      controls.push({ id: control.id, checkIds: [...checks].sort() });
    }
  }
  controls.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return {
    package: pkg.name,
    version: pkg.version,
    benchmarkVersion: oasb.OASB_1_VERSION,
    count: controls.length,
    controls,
  };
}

function payloadIds() {
  const payloads = require(resolve(dir, "dist/attack/payloads/index.js"));
  const ids = payloads.ALL_PAYLOADS.map((payload) => payload.id);
  if (ids.some((id) => typeof id !== "string")) fail("a payload id is not a string");
  const sorted = [...new Set(ids)].sort();
  if (sorted.length !== ids.length) fail("ALL_PAYLOADS repeats an id");
  return {
    package: pkg.name,
    version: pkg.version,
    count: sorted.length,
    payloadIds: sorted,
  };
}

process.stdout.write(JSON.stringify(GENERATORS[name](), null, 2) + "\n");
