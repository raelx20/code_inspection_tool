# VisionGuard — Milestone Checkpoints

Running log of milestone gates for the VisionGuard subsystem (CodeSentry extension).
Checkpoint template follows the Master Development Prompt §2. Every checkpoint is
evidence-based: tests run, counts recorded, files listed — never "it compiles".

**Baseline (recorded before any change, M0):**

```
node scripts/test-runner.js all
ℹ tests 324   ℹ suites 85   ℹ pass 321   ℹ fail 3   ℹ skipped 0   ℹ todo 0   ℹ duration_ms ~18.5k
```

The 3 pre-existing failures (must remain exactly 3, and are **not** attributable to VisionGuard):

| Test | Nature |
|---|---|
| `tests/integration/pipeline.test.js:203` mock OpenRouter severity `MEDIUM !== HIGH` | pre-existing mock/parser logic |
| `tests/unit/cli/auth.test.js:160` key `'your_openrouter_api_key_here' !== 'sk-or-v1-existing'` | environment-dependent (real `~/.codesentry/config.json`) |
| `tests/unit/cli/auth.test.js:174` `isConfigured true !== false` | environment-dependent (same cause) |

Environment notes: Node v24.16.0 / npm 12.0.2 on Windows; `npm install` run once to install the
declared dep `dotenv` (lockfile still contains exactly `node_modules/dotenv`); no lint/format
tooling exists in the repo, so "static checks" = `node --check` on all `src/` + `bin/` JS files
plus the full suite.

**Pre-existing repo observations (recorded at M0, NOT caused by VisionGuard):**

| Observation | Evidence | Consequence for later milestones |
|---|---|---|
| The CI `security-gate` command `scan . --severity BLOCKER --gate` exits **1** on a clean checkout | 38 BLOCKER findings across 22 files (test fixtures + `src/cli/fixer/rules.js`, `src/analyzers/ai/openrouter.js`, `src/cli/demo.js`); `.codesentryignore` lives in `CodeSentry/` but CI scans the repo root, so `tests/fixtures/` is never ignored (`ignore.js:21` reads only `<projectPath>/.codesentryignore`) | M8 must **not** claim the existing gate is green and must not chain VisionGuard's gate onto it; VisionGuard gating is additive and separate |
| Scanning `CodeSentry/` instead still yields 15 BLOCKER findings in shipped source/tests | same command with `scan CodeSentry` | pre-existing; out of scope, must not be "fixed" by weakening checks |
| 3 suite failures are environmental/pre-existing | table above | regression bar is `321 pass / 3 fail`, not 324/0 |

---

## Milestone 0 Status — Repository Reconnaissance

- **Status: PASS**
- **Files changed:** none (environment setup only: `npm install` → `dotenv`; zero source/test/config edits, verified by mtime audit of `src/`, `bin/`, `tests/`)
- **Features implemented:** n/a — reconnaissance only
- **Tests added:** 0
- **Tests passed / failed:** 321 / 3 (the 3 recorded above)
- **Existing suite result (count before vs after):** before `324/85/321/3`, after `324/85/321/3` — **no regression**, run twice to prove stability
- **Security issues found (and fixed / open):** none introduced; 3 pre-existing test failures analyzed (2 environment-dependent, 1 pre-existing mock mismatch) — open, out of scope for VisionGuard
- **Performance issues found:** n/a
- **Technical debt:** baseline carries 3 failing tests; every future checkpoint must compare against `324/321/3`, not against a green suite
- **Remaining work:** M1 design document

**Is this milestone genuinely complete and safe to build upon? → YES.**
Evidence: two identical full-suite runs; dependency scan proving only `dotenv` is required and
only by `bin/codesentry.js`; CLI smoke tests (`help` → 0, `version` → 0); direct inspection of
`schema.js`, `scan.js`, `commands.js`, `config.js`, `scoring.js`, `verdict.js`, `risk-graph.js`,
`modelshield.js`, `deployguard.js`, `discovery/*`, `output.js`, `report.js`, `test-runner.js`,
`ci.yml` — every integration point cited in the report was read, not assumed.

---

## Milestone 1 Status — Architecture Design (no implementation)

- **Status: PASS**
- **Files changed:** none in `src/`, `bin/`, `tests/` (mtime audit: `NONE`)
- **Files added:** `CodeSentry/docs/visionguard/design.md` (design document only — implementation is explicitly out of scope for M1)
- **Features implemented:** none (by design)
- **Tests added:** 0
- **Tests passed / failed:** 321 / 3 — full suite re-run after writing the doc: `324 tests / 85 suites / 321 pass / 3 fail`
- **Existing suite result (count before vs after):** `324/321/3` → `324/321/3` — **no regression**
- **Static checks:** `node --check` over every file in `src/` and `bin/` → `syntax_errors=0`; Markdown additions cannot affect CI scanning because `discovery/language.js` maps only `.js/.ts/.py` extensions
- **Byte-identity proof (A/B):** `scan . --no-ai --severity BLOCKER --no-report --json` was run twice — once *with* the new docs, once *with both docs moved out of the tree* — then normalized (duration/timestamp zeroed) and compared: `fullResultIdentical=true`, 257,393 bytes both ways, 38/38 blockers, identical `(file,line,rule)` sets and identical finding IDs. **VisionGuard's presence changes CodeSentry's output by zero bytes.**
- **Security issues found (and fixed / open):** none new; the design's threat model (T1–T16) enumerates attacker capabilities and states explicitly what is **not** defended (§10) and the 8 known limitations (§13)
- **Performance issues found:** n/a (design specifies streaming 1 MiB hashing, O(n) diffing, single read per file, and a measurement plan for M11)
- **Technical debt:** design decisions to be validated during implementation: Ed25519 via `node:crypto` (no new dep), O_APPEND+lock log appends on Windows, integer-only numbers in hashed fields (documented deviation from full JCS)
- **Remaining work:** M2 (canonical JSON + streaming hasher + safe path resolver + limits)

**Design review performed (M1 exit criteria):**

1. *Internally consistent?* Yes — verdict truth table (§8.2) guarantees `VERIFIED` is unreachable
   unless every dimension is checked, all signatures verify, and an out-of-band anchor matches;
   record hashing, chain hashing and Merkle domain separation use one canonical serializer.
2. *Reuses existing infrastructure?* Yes — `createFinding`/`registerNormalizer`/`OutputHandler`/
   `theme`/`SoftwareRiskGraph`/`node:test` conventions reused; only 5 existing files get thin,
   guarded seams (table in §2), each with a stated reason it cannot break existing behavior;
   `scan.js`, `scoring.js`, `verdict.js`, `modelshield.js`, `deployguard.js`, `discovery/*` are
   explicitly untouched; `discovery/files.js` is explicitly **rejected** for dataset walking
   (it skips image extensions — exactly CV data).
3. *Threat model explicit about non-defense?* Yes — "Explicitly NOT defended" list in §10 plus
   residual-risk column for partially defended rows (T5, T6, T8) and §13 limitations.

**Is this milestone genuinely complete and safe to build upon? → YES.**
Evidence: zero source files modified (mtime audit), full suite identical to baseline
(`324/321/3`), `node --check` clean, design doc contains the module layout, public interfaces,
schemas, storage layout, verification flow, error codes, CLI/exit-code plan, findings/verdict/
report/risk-graph/ModelShield/CI integration plan, threat model, test plan and the top-10
design-failure review required by the Master Development Prompt §4-M1.

---

## Milestone 2 Status — Artifact Hashing Foundation

- **Status: PASS**
- **Files changed:** zero pre-existing files (mtime audit: extraction finalized 12:07:11; every
  file written in this session is `src/visionguard/*`, `tests/unit/visionguard/*`, or
  `docs/visionguard/design.md`). The only edit to an existing file is design §11.1's error-code
  list (documentation only — CodeSentry's scanner never reads `.md`).
- **Files added (10):** `src/visionguard/{errors,canonical,limits,hash,paths}.js` and
  `tests/unit/visionguard/{errors,canonical,limits,hash,paths}.test.js`
- **Features implemented:** `VgError` + 28-code registry; canonical JSON (sorted keys, UTF-16
  safe integers only, depth ≤ 32, lone-surrogate/`__proto__`/sparse-array/class-instance
  rejection, parse ≤ 8 MiB); `hashRecord` (`sha256:` prefix, `record_hash`/`signature` excluded);
  streaming SHA-256 hasher (1 MiB chunks, `O_NOFOLLOW` open, lstat→open→fstat→re-stat TOCTOU
  chain → `VG_RACE_DETECTED`); Merkle root with `0x00`/`0x01`/`0x02`/`0x03` domain tags +
  `visionguard:dataset:empty:v1`; path normalization (NFC, NUL/control/bidi/lone-surrogate,
  traversal/absolute/length rejection, root containment, NFC + case-fold collision detection);
  limits registry (`maxFiles/maxFileSize/maxTotalBytes/maxDepth/maxMetadataBytes/...`).
- **Tests added:** 103 across 14 suites (NIST `''`/`abc` vectors, chunk sizes 0/1/CHUNK±1,
  6 file sizes, hostile path inputs, Merkle determinism/domain separation/order independence,
  TOCTOU `assertStableStats` matrix, every limit boundary). 3 auto-skip on Windows (2 symlink,
  1 chmod — platform capabilities, verified by probe in M0).
- **Tests passed / failed:** `100 / 0` VisionGuard (`node --test tests/unit/visionguard/*`,
  exit 0); full suite `421 / 3`
- **Existing suite result (count before vs after):** baseline `324 tests / 85 suites / 321 pass /
  3 fail` → now `427 tests / 99 suites / 421 pass / 3 fail / 3 skipped` — **+103 tests, +100
  passes, same 3 pre-existing failures** (`pipeline.test.js:203`, `auth.test.js:160`,
  `auth.test.js:174`, identical locations to baseline) ⇒ **no regression**
- **Static checks:** `node --check` over every `.js` in `src/`, `bin/`, and the new tests →
  `syntax_errors=0`; no comments added to code files; no new dependencies (`node:crypto` only)
- **Security issues found (and fixed / open):**
  1. *Fixed:* hashing a FIFO/device could block forever — added `!isFile()` rejection at lstat
     time, before `open()`; fstat check retained against swap-after-open.
  2. *Fixed:* `JSON.parse('{"__proto__":...}')` own-keys are rejected by the `FORBIDDEN_KEYS`
     guard (regression-tested against both literal and parsed input).
  3. *Fixed:* `findPathCollisions` crashed (`TypeError`) on non-string entries → `VG_INTERNAL`.
  4. *Fixed during review:* `./` prefix and `//` handling — `.` segments stripped, empty
     segments rejected (the original collapsing regex made `a//b` undetectable).
  5. *By design:* lone surrogates, control chars, bidi overrides, NUL bytes rejected in both
     canonical strings and paths; sparse arrays and non-plain objects rejected; signature field
     excluded from `hashRecord` (envelope fields hashed separately).
  6. *Open (documented):* `O_NOFOLLOW` is `undefined` on Windows → a sub-millisecond symlink
     TOCTOU window remains between lstat and open; symlink creation needs admin rights here so
     the on-disk guard tests auto-skip. To be noted in §13 limitations during M11/M13.
- **Performance issues found:** 2 GiB sparse file hashed with asserted heap growth < 128 MiB
  (buffer reuse confirmed); whole VisionGuard suite 3.3 s; full suite 14.6 s for 427 tests
- **Technical debt:** `merkleRoot` re-sorts entries per call (O(n log n), fine until datasets are
  walked twice); `hashFile` duplicates a close in `finally` (harmless EBADF-catch);
  `canonicalDigest`/`hashRecord` share but do not centralize the SHA-256 prefix helper; case-fold
  collision detection uses `toLowerCase()` (no locale-aware Turkish-I handling — deterministic,
  documented)
- **Remaining work:** M3 (manifest schema + dataset walk + registration) per design §4–§5;
  `TOOLS`/normalizer seam and `toFindingCode()` mapping deferred to M8 as planned
- **Design doc updated:** §11.1 now lists `VG_PATH_INVALID`, `VG_CANONICAL_INVALID`,
  `VG_LIMIT_METADATA` (added during implementation; `errors.js` is the source of truth)

**Is this milestone genuinely complete and safe to build upon? → YES.**
Evidence: 103 new tests all green (exit 0) including NIST vectors and a 2 GiB bounded-memory
run; full suite `427/421/3` with the identical 3 pre-existing failures at identical locations;
`node --check` clean on everything; zero pre-existing files modified (timestamp evidence);
hostile-input matrix (traversal, absolute, NUL, bidi, lone surrogate, `__proto__`, floats,
sparse arrays, duplicate/colliding paths, race/size/depth/count limits) asserted by tests
rather than assumed; no new dependencies, no comments, no scanner-visible files changed.

---

## Milestone 3 Status — Dataset Walk, Manifest & Registration

- **Status: PASS**
- **Files changed:** zero pre-existing CodeSentry files (audit: since session start only
  `docs/visionguard/design.md` — M3 amendments below — and this log were written outside
  `src/visionguard/` + `tests/unit/visionguard/`)
- **Files added (6):** `src/visionguard/{walk,manifest,store}.js` and
  `tests/unit/visionguard/{walk,manifest,store}.test.js`
- **Features implemented:**
  - `walk.js` — dedicated dataset walker (explicit non-reuse of `discovery/files.js`):
    `lstat`-first, DFS with depth cap, sorted deterministic traversal, image extensions included
    (`.png/.jpg` regression-tested), NFC-normalized identity paths, backslash/control/bidi/NUL
    rejection, symlink exclusion (`VG-DATA-005`, strict ⇒ registration error), special-file skip
    (`VG-DATA-011`), extension policy (`VG-DATA-012`, case-insensitive, recorded in manifest),
    per-rule finding cap 100 with exact `findingCounts`, NFC/case-fold collision detection
    (`VG_NFC_COLLISION`/`VG_CASE_COLLISION`), register mode **throws** vs verify mode
    **collects** (`unreadable[]`) for per-file failures, full limit enforcement
    (files/dirs/size/total/depth).
  - `manifest.js` — §4.1 dataset manifest: structural `validateDatasetManifest` (strict-mode
    unknown-field rejection, schema **major** version gate → `VG_MANIFEST_VERSION`, canonical
    path enforcement inside `files[]`, actor/name/version/timestamp/policy shape checks),
    `parseDatasetManifest`, `checkManifestConsistency` (record_hash vs body, merkle vs file
    list, counts), `buildDatasetManifest`, path-keyed `diffDataset` with same-hash rename
    pairing, `verifyDataset` → status `FAIL|UNANCHORED` with `VG-DATA-001..012` findings,
    `registerDataset` (walk → build → optional atomic store write).
  - `store.js` — `.visionguard/manifests/dataset/<name>/<version>.json`: validated name/version
    path building (traversal-proof), atomic temp+fsync+rename writes, size-capped load,
    `lstat`-based manifest loading (symlinked manifests rejected), `VG_NOT_REGISTERED` on
    missing, containment guard refusing a store inside the dataset root (realpath-aware).
- **Tests added:** 66 total — `walk.test.js` 21, `manifest.test.js` 29, `store.test.js` 15,
  plus 1 directory-limit case added to the existing `limits.test.js` — covering the design §12
  M3 matrix:
  valid/modified/corrupted(size-unchanged)/deleted/added/renamed/empty/duplicate-content/
  nested/unsupported-ext/symlink-in-and-out/permission-error/large-file/case+NFC-collision/
  tampered-manifest (record_hash **and** root-vs-file-list)/malformed-JSON/wrong-schema-version,
  plus diff pairing units, store atomicity/round-trip/limit/containment, and directory-bomb
  limits. 10 platform skips (Windows cannot create symlinks/fifos, enforces owner-read, or
  store case/NFC-distinct names) — each guarded by `t.skip` with an explicit reason.
- **Tests passed / failed:** VisionGuard total `156 / 0` (169 tests, 23 suites, exit 0);
  full suite `477 / 3`
- **Existing suite result (count before vs after):** M2 end `427/421/3` → now
  `493 tests / 108 suites / 477 pass / 3 fail / 13 skipped` — **+66 tests, +56 passes,
  same 3 pre-existing failures at identical locations** (`pipeline.test.js:203`,
  `auth.test.js:160`, `auth.test.js:174`) ⇒ **no regression**
- **Static checks:** `node --check` over `src/`, `bin/` and all 8 VisionGuard test files →
  0 errors (the only failing files are pre-existing intentional `tests/fixtures/*` parsers);
  no comments in code files; no new dependencies
- **Security issues found (and fixed / open):**
  1. *Fixed (self-review):* directory-bomb — unbounded sibling breadth could grow the DFS stack
     without limit ⇒ added `maxDirs: 100000` to `DEFAULT_LIMITS` + `VG_LIMIT_DIR_COUNT`
     (design §5.5/§11.1 updated).
  2. *Fixed:* unreadable files double-reported as both `removed` (002) and `unreadable` (008) —
     `diffDataset` now excludes unreadable paths from the removed set (Linux CI would have
     failed the strict findings assertion).
  3. *Fixed:* manifests reached through a symlink are rejected at load (`lstat`, not `stat`) —
     closes read-through of an arbitrary target as a "manifest".
  4. *Fixed:* `assertStoreOutside` now realpaths the dataset root (symlinked roots no longer
     fool the containment guard).
  5. *Fixed:* walker previously rejected every NFD (decomposed) filename as non-canonical —
     would have broken macOS registration; now identity paths are NFC-normalized while hashing
     uses the raw dirent name, and true collisions fall to the collision detector.
  6. *Fixed:* `a\\b` (literal backslash names) no longer collapse into a fake nested path —
     rejected as `VG_PATH_INVALID` on registration, collected as unreadable on verification.
  7. *Open (documented):* extension-excluded files are invisible to verification by design
     (policy defines scope); symlink TOCTOU window on Windows from M2 remains; hostile
     filenames collected in `unreadable[]` are emitted raw — CLI layer (M9) must sanitize.
- **Performance issues found:** full suite 14.8 s for 493 tests; walker sorts per directory and
  once globally (O(n log n)); finding arrays capped at 100 per rule so a filter-heavy dataset
  cannot inflate manifests past `maxManifestBytes` (also enforced at save/load)
- **Technical debt:** `registerDataset` lives in `manifest.js` (facade `index.js` comes later);
  `store.js` handles datasets only (store.json, provenance log + lock land in M5);
  rename pairing is a same-hash greedy heuristic (documented §14 runner-up); empty-dataset
  finding fires from `file_count === 0` rather than walk stats (identical in practice)
- **Design doc amended (recorded here):** §5.5 `maxDirs`, §11.1 `VG_LIMIT_DIR_COUNT` +
  `VG_LIMIT_MANIFEST`, §9.1 `VG-DATA-012` row, §2 richer `walk.js`/`manifest.js` signatures and
  the `walk.test.js`/`store.test.js`/`errors.test.js` test files
- **Remaining work:** M4 — model registration (`model.js`: magic-byte format sniffing, zero
  deserialization, `registerModel`/`verifyModel`, pickle signal `VG-MODEL-005`)

**Is this milestone genuinely complete and safe to build upon? → YES.**
Evidence: 66 new tests green (169-test VisionGuard suite exits 0) including the full §12 M3
tamper matrix — every single-tamper scenario asserts the exact expected `VG-DATA-*` rule and a
`FAIL`/`UNANCHORED` status; both manifest-tamper variants (record_hash mismatch **and**
files-vs-merkle-root disagreement with a self-consistent record_hash) are distinguished by
`manifestConsistency`; full suite `493/477/3` with the identical 3 pre-existing failures;
`node --check` clean; zero pre-existing CodeSentry files modified; four security gaps found and
fixed during self-review (directory bomb, unreadable double-report, symlinked-manifest read,
realpath containment); no new dependencies, no comments.

---

## Milestone 4 Status — Model Registration & Verification

- **Status: PASS**
- **Files changed:** zero pre-existing CodeSentry files outside VisionGuard (design §9.1 amended
  — `VG-MODEL-006` row — and this log; documentation only). Within VisionGuard, two M3 files
  were refactored as planned: `manifest.js` (extracted/exported `assertLabel`, exported
  `toIso`/`NAME_RE`/`TIMESTAMP_RE`/`RECORD_HASH_RE` for reuse; `assertNameVersion` now delegates
  to `assertLabel` with byte-identical messages) and `store.js` (shared `saveManifestTo`/
  `readManifestText` internals behind the dataset save/load functions + new
  `modelManifestPath`/`saveModelManifest`/`loadModelManifest`).
- **Files added (2):** `src/visionguard/model.js`, `tests/unit/visionguard/model.test.js`
- **Features implemented:**
  - `sniffFormat(head, size, fileName)` — extension + magic sanity check, **zero
    deserialization**: safetensors (u64-LE header length `0 < N ≤ 100 MiB`, `8+N ≤ size`,
    `head[8] == 0x7b`; header JSON `parse`d only when `N ≤ 1 MiB`, plausibility-only above;
    invalid JSON/array ⇒ not safetensors), `.onnx` ⇒ protobuf byte `0x08`, `.pt/.pth` ⇒ zip
    (`PK\x03\x04`, not pickle) or pickle head (`0x80`+proto 1–6, or first byte `0x63`/`0x28`)
    else magic failure, everything else ⇒ `other` (magicOk); empty ⇒ magicOk false.
  - `family(format)` — safetensors | onnx | torch(pt,pth) | other; registration and validation
    require `family(format) === family(detected_format)` **and** `magicOk`.
  - `readSniffHead(absPath, hashFileResult)` — bounded read (9-byte probe; `8+N` bytes only for
    `N ≤ 1 MiB`), lstat + `O_NOFOLLOW` open, fstat before/after with `assertStableStats`, plus a
    cross-check of ino/dev/size/mtimeNs against the hashFile identity → `VG_RACE_DETECTED`.
  - `assertMetadata` — plain object, container depth ≤ 6, canonical bytes ≤ 4096
    (`VG_LIMIT_METADATA`), floats/sparse/non-plain → `VG_CANONICAL_INVALID`.
  - `validateModelManifest`/`parseModelManifest` — strict unknown-field rejection, schema major
    version gate, label checks, format-family cross-field rule, size ≥ 1, raw-hex `sha256`,
    RFC3339-ms `created_at`, actor, metadata, `record_hash`/`signature` shape.
  - `registerModel` — label/format/actor/metadata validation → lstat (symlink →
    `VG_SYMLINK_DENIED`, not-a-file → `VG_UNREADABLE`, zero-byte → `VG_MANIFEST_SCHEMA`) →
    `assertFileSize` → `hashFile` → sniff → family+magic gate → `record_hash` → optional atomic
    store write to `manifests/model/<id>/<version>.json`.
  - `verifyModel` — findings in order `006` (record_hash tampered) → `001` (missing/symlink/
    changed/inspecting-race) → `003` (empty; suppresses 001/002) → `002` (detected differs or
    magic broken) → `005` (pickle signal, HIGH); status `FAIL` on any BLOCKER else `PASS`
    (models are anchor-free per §8.1); returns `expected`/`actual`/`manifestConsistency`.
- **Tests added:** 39 — `model.test.js` 38 (sniff units incl. good/truncated/bad-JSON/huge-header
  safetensors, onnx ok/bad, pt zip/pickle/PNG, png→other, empty; registration matrix: valid,
  unsupported format, family mismatch, magic mismatch, empty, missing, bad id, symlink,
  metadata depth/bytes/float; verification matrix: PASS, in-place modify, same-size replace,
  truncated `[001,002]`, emptied `[003]`, deleted `[001]`, store-tampered `[006]`,
  pickle canary `[005]`+PASS, magic-swapped `[001,002]`, `other` roundtrip; strict/version/kind/
  family/size/record_hash validation) + 1 model save/load/unregistered block in `store.test.js`.
- **Tests passed / failed:** VisionGuard total `194 / 0` (208 tests, 27 suites, exit 0);
  full suite `515 / 3`
- **Existing suite result (count before vs after):** M3 end `493/108/477/3/13` → now
  `532 tests / 112 suites / 515 pass / 3 fail / 14 skipped` — **+39 tests, +38 passes,
  same 3 pre-existing failures at identical locations** (`pipeline.test.js:203`,
  `auth.test.js:160`, `auth.test.js:174`) ⇒ **no regression**
- **Static checks:** `node --check` over `src/`, `bin/` and all VisionGuard tests → 76 files,
  0 errors; no comments in code files; no new dependencies
- **Security issues found (and fixed / open):**
  1. *Fixed (self-review):* TOCTOU window between `hashFile` and the sniff read — a swap after
     hashing could record a `detected_format` for bytes other than the hashed ones. `readSniffHead`
     now fstats before/after and compares ino/dev/size/mtimeNs against the hashFile identity →
     `VG_RACE_DETECTED` (register throws; verify folds it into `VG-MODEL-001`).
  2. *Fixed (test red, then code):* metadata depth counter counted primitive leaves as levels
     (a 7-object nest reported depth 8) → containers-only counting; tests pin 6-deep allowed,
     7-deep rejected.
  3. *Proven by canary:* a `.pt` file whose bytes contain `echo pwned > marker.txt` registers
     and verifies (`PASS` + `VG-MODEL-005` HIGH) and the marker file is asserted **never
     created** — sniffing reads ≤ 9 bytes (or ≤ 8+1 MiB of safetensors JSON) and never
     deserializes/executes payload bytes.
  4. *By design:* model registration skips `assertStoreOutside` (single file, no walk — the
     store cannot corrupt anything by adjacency); symlinks rejected by lstat + `O_NOFOLLOW`
     exactly like datasets; `VG-MODEL-001..006` severity map exported as the M8 contract.
  5. *Open (documented):* torch `.bin` weights are rejected in v1 (must be renamed
     `.pt`/`.pth`); safetensors headers > 1 MiB are validated by plausibility only
     (`SNIFF_PARSE_LIMIT`, hashing still covers content); `VG-MODEL-004` (unregistered)
     emission deferred to the assurance layer in M7+; Windows symlink tests auto-skip (EPERM)
     so on-disk symlink coverage runs on Linux CI.
- **Performance issues found:** sniffing is O(header) — ≤ 9 bytes for non-safetensors, bounded
  `8+N` ≤ 1 MiB for safetensors; full suite 15.0 s for 532 tests; VisionGuard suite 7.5 s
- **Technical debt:** `sniffFormat` needs the file name (extension participates in detection for
  `onnx`/`pt`/`pth` — documented design choice); `readSniffHead` is coupled to a `hashFile`
  result object (internal contract, exported for tests); `registerModel`/`verifyModel` live in
  `model.js` (facade `index.js` arrives later)
- **Design doc amended (recorded here):** §9.1 `VG-MODEL-006` row (model manifest tampered →
  BLOCKER) — the finding is emitted by `verifyModel` when `hashRecord(manifest) !== record_hash`
- **Remaining work:** M5 — signing + provenance store (`store.json`, append-only
  `provenance.log` with O_APPEND + lock + fsync, Ed25519 via `node:crypto`, private keys in
  `~/.codesentry/visionguard/keys/`)

**Is this milestone genuinely complete and safe to build upon? → YES.**
Evidence: 39 new tests green (208-test VisionGuard suite exits 0) including the full §12 M4
matrix — every tamper scenario asserts the exact expected `VG-MODEL-*` rule list and status;
the canary test executes neither the pickle payload nor any subprocess; sniff units pin every
magic branch (safetensors good/truncated/bad-JSON/huge, onnx, zip, pickle, PNG, empty); full
suite `532/515/3` with the identical 3 pre-existing failures at identical locations;
`node --check` clean on 76 files; zero pre-existing CodeSentry files modified; two self-review
findings fixed (hash/sniff TOCTOU, depth counter); no new dependencies, no comments.

---

## M5 — Ed25519 signing + provenance store

**Status: PASS** (design amended, 69 new tests, full suite green modulo the 3 pre-existing failures)

### What shipped (code)

| File | Change |
|---|---|
| `src/visionguard/keys.js` | **new** — Ed25519 via `node:crypto` only: keygen, `key_id = sha256(DER)[0:32]`, private key files under `keyDir` (created `wx`, mode 0600), `signRecordHash`/`verifySignature` (base64, 64-byte sig, `false` never throws), self-signed public key **records** (`kind: 'key'`), key record hash + signature validation (key-id recomputed from DER — substitution cannot keep the id; unsigned record allowed only when `status: revoked`) |
| `src/visionguard/provenance.js` | **new** — record build/validate (`record_id === record_hash`, kind rules for `contributor_registered` / `artifact_registered` / `operation_recorded` / `inference_recorded`), `parseProvenanceLog` (full read, line numbers, malformed entries), `appendRecord` (chain-extends under the log lock, refuses broken/non-genesis/duplicate chains with `VG_MANIFEST_MALFORMED`), `registerContributor` (genesis record + pinned key set, key material cleaned up if append fails), `recordOperation` (signer must be registered + active + authorized for the operation), `recordArtifact`, `verifyProvenance` → findings `VG-PROV-001..011` + warnings `W001..W004`, status `PASS / FAIL / NOT_CHECKED / UNSIGNED / UNANCHORED` |
| `src/visionguard/metadata.js` | **new** — `metadataDepth`/`assertMetadata`/`METADATA_MAX_DEPTH=6` extracted from `model.js` (re-exports preserved; `model.test.js` 37 pass / 1 skip unchanged) |
| `src/visionguard/store.js` | `store.json` build/validate/save/load (self-hashed), `provenance.log.lock` advisory lock (`wx`, ≤2 s retry, 30 s stale-steal, released on throw), `appendLogLineUnlocked`/locked append (newline guard, `VG_LIMIT_LOG`), `readProvenanceText` (whole-file read bounded by `maxLogBytes`, **symlink rejected** on read *and* append) |
| `src/visionguard/canonical.js` | `RECORD_ID_FIELD` — `record_id` excluded from `record_hash` (record_id := record_hash is circular; manifests unaffected) |
| `src/visionguard/errors.js` | `VG_LIMIT_LOG` |
| `src/visionguard/model.js` | refactor only — delegates to `metadata.js` |

### Design decisions recorded this milestone (design.md amended)

1. **§4/§5.1** `record_hash` excludes exactly `{record_id, record_hash, signature}`; `signature` signs the `record_hash` string.
2. **§6** log reads are **whole-file, not windowed** (bounded by `maxLogBytes` → `VG_LIMIT_LOG`), so front truncation cannot hide behind an unread tail window; first record must be genesis (`prev_record_hash === null`); log must be a regular file (symlink → `VG_SYMLINK_DENIED`); verify snapshots under the writer lock.
3. **§8.1** Provenance dimension gains `UNANCHORED` (chain + signatures valid but no matching expected head); `UNSIGNED` now fires when **any** record lacks a signature (was "no signatures at all").
4. **§9.1** `VG-PROV-003` documented as **key pinning** (contributor registration pins allowed `key_id`s; spare key cannot forge for a known contributor); warning rules `VG-PROV-W001..W004` (non-monotonic timestamp, unverifiable artifact ref, operations mismatch, signer with no registration) — severity `WARN`, never flip a dimension to `FAIL`.
5. **§11.1** `VG_LIMIT_LOG`; **§2** module table: `keys.js`, `metadata.js` (+tests).

### Evidence (commands run, counts)

```
node --test "tests/unit/visionguard/*.test.js"
  tests 277  suites 39  pass 262  fail 0  skipped 15      (was 208/27/194/0/14 → +69 tests)
node scripts/test-runner.js all
  tests 601  suites 124  pass 583  fail 3  skipped 15
  the 3 failures are exactly the pre-existing trio at
  pipeline.test.js:203 / auth.test.js:160 / auth.test.js:174
node --check over src/ + bin/ + tests/unit/visionguard (excl. fixtures)
  checked=81  failures=0
```

Tests: `keys.test.js` 18, `provenance.test.js` 37, `store.test.js` 27 (+11 M5), `canonical.test.js` 35 (+2).
Full §12 M5 matrix covered: keygen/self-signed/key-id recompute/key substitution, store.json
roundtrip+tamper, lock fresh/stale/contended/throw-release, log size limit, multi-contributor
DAG chain, missing/forward parent, altered record, unauthorized/revoked/unregistered signer,
wrong dataset/model ref cross-check (`VG-PROV-011`), edit/delete/reorder/truncate/duplicate
(front+tail vs anchor), forged signature, unsigned → `UNSIGNED`, conflicting versions,
cycle, concurrent appends (4 child processes, chain stays valid), crash-mid-write, replay,
finding caps (100/rule), warnings, anchor file, genesis check, symlink-through-log.

### Self-review findings fixed before sign-off

1. **Nested lock deadlock** — the verify-snapshot edit initially landed inside `appendRecord`,
   re-entering the same lock file once the log existed (every second append failed with
   `VG_STORE_LOCKED`). Detected by the suite going 37/37 → 26 fails; restored plain read
   inside the append lock and applied the snapshot lock to `verifyProvenance` where it belongs.
2. **Symlink write-through** — `open(log, 'a')` follows symlinks: an attacker replacing
   `provenance.log` with a link would redirect appends at an arbitrary file. Both read and
   append now `lstat` and reject with `VG_SYMLINK_DENIED` (test skips on win32 EPERM).

### Performance / debt

- Full suite ~24–56 s for 601 tests (parallel variance).
- Debt: `verifyProvenance` is a single function (per-check helpers arrive with M8's report
  shaping); key records are pretty-printed JSON like manifests (hashed canonically on load);
  `expectedHead` that is whitespace-only is treated as "provided" (fail-loud on empty CI var).
- **No new dependencies, no comments in code, no pre-existing CodeSentry file modified**
  (mtime audit still clean except `*visionguard*` + `MILESTONE_CHECK.md`).

**Is this milestone genuinely complete and safe to build upon? — YES.**
Evidence: 69 new tests, 0 failures, exact §12 matrix coverage, two self-review defects found
and fixed with regression tests, full suite identical to baseline modulo the 3 documented
pre-existing failures, `node --check` clean on 81 files.

---

## M6 — Pipeline identity + inference records

**Status: PASS** (design amended, 50 new tests, full suite green modulo the 3 pre-existing failures)

### What shipped (code)

| File | Change |
|---|---|
| `src/visionguard/pipeline.js` | **new** — `computePipelineIdentity()` (§4.4 identity: preprocess config, code files hashed from root with lstat/symlink rejection or trusted precomputed `sha256`, dependency lock, `parameters` under metadata caps, `runtime` via `readRuntimeFacts()` which reads `package-lock.json`/`package.json` **without importing untrusted code**), `registerPipeline()` (manifest wrapper at `manifests/pipeline/<name>/<version>.json`, optional Ed25519 signature, `pipeline_id = hashRecord(identity)`), `parsePipelineManifest`/`validatePipelineManifest` (recomputes **both** `pipeline_id` and `record_hash` at load → `VG_MANIFEST_HASH_MISMATCH`), `verifyPipeline()` → `VG-PIPE-001` |
| `src/visionguard/inference.js` | **new** — `recordInference()` (kind `inference_recorded`, `inputs = [input, model, pipeline]`, `outputs = [output]`, `metadata.params` + `output_mode`, signer must be authorized for `infer`), `verifyInference()` → findings `VG-INFER-001..003`, `VG-PIPE-001`, `VG-OUT-001..003` with separate inference/`output_status` per §8.1, `compareVersions()` (numeric per-segment) |
| `src/visionguard/store.js` | `pipelineManifestPath`/`savePipelineManifest`/`loadPipelineManifest` (lazy-requires `./pipeline`, same pattern as model) |
| `src/visionguard/provenance.js` | `validateRecord` inference shape rules (exactly 3 inputs — one loose, one `model/…@…`, one `pipeline/…@…` — exactly 1 output, `output_mode` enum); `loadArtifactManifest` + cross-check now cover `pipeline/` refs (compare against `pipeline_id`); extracted `readLogText()` (lock-wrapped whole-file read) used by `verifyProvenance` and `verifyInference`; exported `resolveSigner`/`readLogText` |

### Design decisions recorded this milestone (design.md amended)

1. **§2** `pipeline.js` module line lists register/verify.
2. **§4.4** pipeline manifest wrapper documented; load-time recomputation of `pipeline_id` **and** `record_hash` (stricter than dataset/model — identity is self-contained, recompute needs no file access); precomputed-vs-hashed file entries; `verifyPipeline` → `VG-PIPE-001`.
3. **§4.5** inference record validation rules (exact input/output shape, params default, output_mode enum, `infer` authorization) and the full check→rule mapping: input bytes → `VG-INFER-001`, parent placement → `VG-INFER-002`, model registration/staleness/file bytes → `VG-INFER-003`, pipeline registration/hash → `VG-PIPE-001`, output missing → `VG-OUT-002`, swapped (bytes match *another record's* recorded output) → `VG-OUT-003`, other byte mismatch → `VG-OUT-001`; inference status vs `output_status` split; unresolvable byte checks → `NOT_CHECKED`; signatures stay the Provenance dimension's job; §3 `verifyOutput({recordId})` is the M8 facade name for the same function.
4. **§9.1** `VG-PIPE-001`, `VG-INFER-001..003`, `VG-OUT-001..003` expanded from aggregated rows to per-rule conditions.

### Evidence (commands run, counts)

```
node --test "tests/unit/visionguard/*.test.js"
  tests 327  suites 46  pass 311  fail 0  skipped 16      (was 277/39/262/0/15 → +50 tests)
node scripts/test-runner.js all
  tests 651  suites 131  pass 632  fail 3  skipped 16
  the 3 failures are exactly the pre-existing trio at
  pipeline.test.js:203 / auth.test.js:160 / auth.test.js:174
node --check over src/ + bin/ + tests/unit/visionguard (excl. fixtures)
  checked=85  failures=0
mtime audit: 0 files outside *visionguard* + MILESTONE_CHECK.md modified
```

Tests: `pipeline.test.js` 24 (1 platform skip: symlink EPERM on win32), `inference.test.js` 26.
Full §12 M6 matrix covered: valid inference (PASS + anchored `verifyProvenance` PASS),
modified/missing input, modified model file, model hash contradicting registration,
unregistered model reference, stale model version (superseded by `2.0.0`), modified/missing/
malformed (directory) output, outputs swapped between two records (`VG-OUT-003` both ways),
inconsistent metadata (float params rejected by canonical rules at record time — caught as a
test bug: `threshold: 0.5` → `VG_CANONICAL_INVALID`; bad `output_mode`; 8-deep params →
`VG_LIMIT_METADATA`; post-hoc metadata edit → record no longer parseable → `VG-INFER-001`),
missing parent, unregistered/hash-mismatched pipeline ref, wrong-shape inputs, unauthorized
`infer` key, missing/mismatched key file, missing record / wrong kind / no log, byte checks
skipped without `root`, log-level `VG-PROV-011` integration for both ref types.

### Self-review notes

1. **Test-side defect found by the suite**: metadata floats are rejected in hashed positions
   (documented canonical rule); fixed the test to a string threshold instead of weakening
   production code.
2. Resolved intentionally: byte checks degrade to `NOT_CHECKED` (not PASS/FAIL) when artifacts
   are registered refs or no `root` is given — keeps §8.1's Output row honest.
3. Pipeline identity accepts caller-precomputed `sha256` without re-reading (trusted caller
   path, documented); hashing path always lstat-rejects symlinks.

### Performance / debt

- Full suite ~20 s for 651 tests.
- Debt: `verifyInference` re-reads the whole log (bounded by `maxLogBytes`, lock-wrapped) — a
  shared parsed-log cache arrives with M8's `runAssurance`; `readRuntimeFacts` understands
  npm lockfiles only (pip/poetry → empty libraries, documented as declared-runtime best effort);
  `compareVersions` is numeric-per-segment, not semver (no prerelease precedence).
- **No new dependencies, no comments in code, no pre-existing CodeSentry file modified.**

**Is this milestone genuinely complete and safe to build upon? — YES.**
Evidence: 50 new tests, 0 failures, exact §12 M6 matrix coverage, full suite identical to
baseline modulo the 3 documented pre-existing failures, `node --check` clean on 85 files,
zero non-VisionGuard files touched.

---

## M7 — CV Pipeline Demonstration

**Status: PASS** (14 new tests, full suite green modulo the 3 pre-existing failures, demo runs VERIFIED end-to-end)

### What shipped (code)

| File | Change |
|---|---|
| `scripts/visionguard-demo.js` | **new** — self-contained demo + CLI (stdlib only): deterministic dataset generator (32 16×16 grayscale PNGs, 4 shape classes, fixed-seed LCG, **hand-rolled PNG encoder** with stored-deflate zlib blocks + CRC32/Adler32 — byte-identical across OS/Node versions; decoder CRC-validates, bounds-checks and supports all 5 PNG filters); integer area-average 16→8 resize + fixed-point normalization (no floats in any hashed position); nearest-centroid classifier **trained from the registered dataset** and written as a real **safetensors** file (u64-LE header, `__metadata__` classes, F32 LE 4×64 tensor, 8-byte header padding) read back by byte offsets only — zero deserialization of executable content; deterministic inference → `outputs/prediction.json`; orchestration registering 4 least-privilege contributors (A `curate_dataset`, B `preprocess`, C `train`+`export_model`, D `infer`), dataset artifact binding → preprocess op → pipeline manifest+binding → train op → inference record (9 signed records, DAG-parented), out-of-band anchor written to `.visionguard/anchors/head.txt`, per-dimension verification, byte-identical re-execution check, `--json`/`--out`/`--help` CLI with exit codes 0/1/2/3/4, store-reuse guard |
| `tests/unit/visionguard/demo.test.js` | **new** — 14 tests (3 suites): happy path all-PASS+VERIFIED+anchor file+re-execution identical; contributor least-privilege + separate key stores (private `<out>/keys`, public in store); 9-record chain order/actors/prev-links/parents-exist/all-signed/genesis; cross-run artifact determinism (identical merkle_root, model sha256, pipeline_id, output sha256); unauthorized ops (`D→curate_dataset`, `B→infer`, `A→train` → `VG_UNAUTHORIZED_OP`, log unchanged); store-reuse refusal; dataset generation determinism; tamper matrix (one PNG byte → `VG-DATA-001` naming exactly `circle/00.png`; model byte → `VG-MODEL-001 content changed`; output append → `VG-OUT-001` + expected≠actual; input byte → `VG-INFER-001`); PNG roundtrip + CRC-corruption + non-PNG rejection; safetensors roundtrip + `sniffFormat` magic (`safetensors`, `magicOk`, not pickle); CLI spawn (exit 0 + valid JSON, `--bogus` → 2, `--help` → 0) |

### Design decisions recorded this milestone

1. No design.md amendments required — §12's M7 row ("deterministic re-execution equality; four contributors A–D") was implemented as specified; the demo's trust boundary (PNG decoder operates only on demo-generated images, safetensors reader bounds-checks offsets before any read) needs no schema change.
2. Demo artifacts are **generated, never committed**: default workspace is `fs.mkdtempSync(os.tmpdir())`, tests use their own temp roots, and every run writes into a fresh directory (a directory containing a `provenance.log` is refused rather than appended to).
3. The pipeline's declared code reference is a byte-copy of the executing demo script (`pipeline.js`), so the identity hashes the code that actually ran.

### Evidence (commands run, counts)

```
node --test tests/unit/visionguard/demo.test.js
  tests 14  suites 3  pass 14  fail 0  skipped 0
node --test "tests/unit/visionguard/*.test.js"
  tests 341  suites 49  pass 325  fail 0  skipped 16      (was 327/46/311/0/16 → +14 tests)
node scripts/test-runner.js all
  tests 665  suites 134  pass 646  fail 3  skipped 16
  the 3 failures are exactly the pre-existing trio at
  pipeline.test.js:203 / auth.test.js:160 / auth.test.js:174
node --check over src/ + bin/ + scripts/ + tests/unit/visionguard (excl. fixtures)
  checked=88  failures=0
node scripts/visionguard-demo.js        → overall: VERIFIED, exit 0, 964 ms
node scripts/visionguard-demo.js --bogus → exit 2
mtime audit: session wrote only scripts/visionguard-demo.js,
  tests/unit/visionguard/demo.test.js and this log
```

### Self-review findings fixed before sign-off

1. **Predictable temp path** — the re-execution check originally wrote `os.tmpdir()/vg-reexec-<pid>-<time>.json`: a predictable name in a shared directory invites a symlink write-through. Replaced with a private `mkdtemp` directory removed recursively in `finally`.
2. **Wrong module reference** — `prov.recordInference` (lives in `inference.js`, not `provenance.js`) caught by the first smoke run; corrected before tests were written.

### Performance / debt

- Whole demo run **964 ms** (4 Ed25519 keygens, 32 PNG encodes, full dataset+model hashing, 9 signed/locked appends, 5 dimension verifications, anchored provenance verify, re-execution) — far inside the 10 s target.
- Debt: the demo's `overallVerdict` and the dataset PASS/UNANCHORED mapping duplicate §8.1/§8.2 logic in miniature until M8's `assurance.js`/`index.js` exist (the report exposes raw verify results alongside, so M8 can replace the mapping without touching tests); a `VgError` raised by the demo CLI exits 4 — the usage-vs-operational split belongs to M9's command layer; PNG/safetensors codecs live in `scripts/` (not in the published package) and move only if M13 needs them elsewhere.
- **No new dependencies, no comments in code, no pre-existing file modified** (mtime audit clean).

**Is this milestone genuinely complete and safe to build upon? — YES.**
Evidence: 14 new tests, 0 failures, covering the exact §12 M7 requirements (four contributors with least-privilege keys, signed+anchored chain, deterministic re-execution proven both within a run and across two independent runs, tamper detection for all four artifact classes, CLI exit codes); full suite `665/646/3` with the identical 3 pre-existing failures at identical locations; `node --check` clean on 88 files; zero non-session files touched; two self-review defects found and fixed.

---

## M8 — CodeSentry Integration

**Status: PASS** (49 new tests, full suite `714/695/3/16` with only the 3 pre-existing failures, byte-identity proven both ways, all five §2 seams live)

### What shipped (code)

| File | Change |
|---|---|
| `src/visionguard/assurance.js` | **new** (712 lines) — `runAssurance()` orchestrator: store presence/metadata check (unreadable `store.json` → `VG-PROV-001` + forced provenance FAIL; absent file → no effect), provenance verify with anchor resolution, size-vote dataset locate (`VG-DATA-002` fail-closed when registered files are gone), model locate by size+sha256 → size → basename, dataset signed-binding check (record output ref+sha256, `hashRecord` integrity, key load + non-revoked + signature verify), pipeline spec reconstruction from `manifest.identity` (runtime pinned to recorded value), per-record `verifyInference` (worst-of; `modelPath` passed only when the record's model ref matches the located file), `overallVerdict` truth table (`FAIL` dominates → `INTEGRITY VIOLATION`; any required dim ≠ PASS → `INCOMPLETE`; else `VERIFIED`; all six dims always emitted), provenance graph builder (artifacts/contributors/trusts/derivedFrom, deterministic sorts) |
| `src/visionguard/findings.js` | **new** (49 lines) — `reportToFindings()`: report findings+warnings → `createFinding({tool:'visionguard', category:'security', line:null, confidence:'high'})`, `WARN→INFO`, `detail→message`, file fallback `.visionguard/provenance.log` (VG-PROV*) / `.visionguard`, dedupe by finding id |
| `src/visionguard/index.js` | **new** (346 lines) — `createVisionGuard()` async facade (§3: `init/registerDataset/verifyDataset/registerModel/verifyModel/recordOperation/recordPipeline/recordInference/verifyOutput/lineage/verifyAll`, plain objects, `VgError` only for typed operational failures, actor/keyFile state set by `init`); `applyVisionGuardToScan(result, options)` — runs assurance, merges VG findings **bypassing severity/category filters** (anti-dilution, id-deduped), recomputes `aggregation/score/verdict` via core functions (core modules untouched), attaches `result.visionGuard`, injects graph nodes, forces `{status:'FAIL', message:'VisionGuard integrity violation: …'}` **only on `INTEGRITY VIOLATION`** (INCOMPLETE escalates exit only with `requireVerified`), returns `{report, addedFindings, exitCode}`; `injectVisionGraph()` — additive `vg-contributor:*`/`vg-artifact:*` nodes + `TRUSTS`/`DERIVED_FROM` edges, `summary.nodeCount/edgeCount` refreshed to `nodes.size`/`edges.length` |
| `src/findings/schema.js` | seam: `'visionguard'` appended to `TOOLS` |
| `src/cli/commands.js` | seam: `OPTIONS.VISION`/`OPTIONS.REQUIRE_VERIFIED`, parse branches, two help option lines + `codesentry scan . --vision --json` example |
| `bin/codesentry.js` | seam: after `scan()`/`progress.complete`, lazy-require adapter, `visionExitCode = max(scan, vision)`; adapter throw → exit 2 with `output.printError` always on stderr (JSON stdout untouched, proven with hostile store); `--require-verified` read only inside `--vision` |
| `src/cli/report.js` | seam: guarded `_visionGuardSection()` (6-row dimension table, Overall, anchor line, finding counts, verdict note) inserted after DeployGuard; returns `null` without `result.visionGuard` (sections `filter(Boolean)`) |
| `src/cli/formatter.js` | seam: guarded VisionGuard line in **both** `formatSummary` branches (plain: `VisionGuard: <overall>` + dim list; color card: overall + dataset/model/provenance statuses) |
| `tests/unit/visionguard/verdict.test.js` | **new** — 8 tests: six-dim exposure, VERIFIED only when all PASS, FAIL→VIOLATION for every dim incl. mixed/missing, each non-PASS status/missing key → INCOMPLETE, empty/partial sets, `statusOf` normalization, `worstStatus` rank table |
| `tests/unit/visionguard/assurance.test.js` | **new** — 20 tests over 12 independent `fs.cpSync` scenario copies of one demo build: clean VERIFIED (all six PASS, anchored, signed binding, empty findings, graph populated), tamper matrix (dataset byte → `VG-DATA-001`; model byte/missing → `VG-MODEL-001`; pipeline.js append → `VG-PIPE*`; output append → output FAIL while inference PASS; input byte → inference FAIL while output PASS; dataset dir gone → `VG-DATA-002`), anchor deleted → UNANCHORED/INCOMPLETE, wrong anchor head → `VG-PROV-008` FAIL, corrupt `store.json` → `VG-PROV-001`, storeless → six×NOT_CHECKED/INCOMPLETE/zero findings/graph empty, unregistered dataset/model/inference requests → `VG_NOT_REGISTERED`, `reportToFindings` mapping/WARN→INFO/fallback paths/malformed tolerance |
| `tests/unit/visionguard/integration.test.js` | **new** — 21 tests: commands parse+help+unknown-flag, TOOLS/`createFinding` seam, adapter (VERIFIED attach without touching core signals; violation → forced FAIL + exit 1 + `byTool.visionguard` + score penalty; id-dedupe no-double-count; INCOMPLETE exit 0 / `requireVerified` 1; risk-graph injection incl. `CALLS` preservation + summary sync; `riskGraph` absent tolerated), real `scan()` on demo store end-to-end (VERIFIED attach, vg nodes in the live Map, report section + terminal line rendered), guarded absence in report+formatter, forced-violation rendering, facade lifecycle (init → register → verify UNANCHORED → authorized op → unauthorized `VG_UNAUTHORIZED_OP` reject → verifyAll INCOMPLETE) and facade on demo (verifyAll VERIFIED, `verifyOutput` PASS, lineage ancestors ending at the inference record), adapter↔`runAssurance` cross-check |

### Design decisions recorded this milestone

1. **Explicit opt-in flags** (`--vision`, `--require-verified`) rather than store auto-detect: default scans keep byte-identity; `--require-verified` is a no-op without `--vision`.
2. **Forcing rule**: only `INTEGRITY VIOLATION` rewrites `result.verdict`/forces exit 1; `INCOMPLETE` raises exit only under `--require-verified`; scan exit codes win by `Math.max`, adapter operational failure = 2 (stderr message, JSON stdout remains valid).
3. **Anti-dilution**: VG findings merge regardless of `--severity`/`--category`; aggregation/score/verdict are *recomputed* through the core functions — `aggregation.js`/`scoring.js`/`verdict.js`/`scan.js` unmodified.
4. **Graph injection is additive** and confined to post-build (`vg-` prefixed node ids, `TRUSTS`/`DERIVED_FROM` edge types, summary counts refreshed); `toMermaid`/`formatTerminal` render only `attackPaths`, so printed attack output cannot change.
5. **Anchor resolution order**: explicit `anchor.expectedHead` → `anchor.anchorFilePath` → env `VG_EXPECTED_HEAD` → auto `.visionguard/anchors/head.txt` when present → none (UNANCHORED).
6. **Storeless scans** produce six×`NOT_CHECKED`, overall `INCOMPLETE`, zero findings (NOT_CHECKED is not a finding) — verified output, not an integrity claim.
7. **Documented deviation from §9.1**: unreadable `store.json` → `VG-PROV-001` + provenance FAIL (§9.1 has no store rule); absent `store.json` → `{valid:true}`, no effect (the demo never writes one).
8. **Fail-closed registration**: a registered dataset/model that cannot be located under the project root is FAIL, never silently skipped; pipeline verification failures (unreadable manifest, un-recomputable spec) → `VG-PIPE-001` FAIL; model located by size+sha256 → first size match (content tamper then surfaced by `verifyModel`) → basename superset.
9. Report `warnings` map to CodeSentry severity `INFO`; `overallVerdict` never invents dimension keys — all six always present, `FAIL` checked before `INCOMPLETE`.
10. **M9 scope reserved**: `vision` command group, §8.1 six-dimension terminal table, `--store`/`--expected-head` flags, `cli.js` wiring — not touched here.

### Evidence (commands run, counts)

```
node --test "tests/unit/visionguard/*.test.js"
  tests 390  suites 63  pass 374  fail 0  skipped 16      (was 341/49+/325/0/16 → +49 tests)
node scripts/test-runner.js all
  tests 714  suites 148  pass 695  fail 3  skipped 16
  the 3 failures are exactly the pre-existing trio at
  pipeline.test.js:203 / auth.test.js:160 / auth.test.js:174
node --check over src/ + bin/ + scripts/ + tests/ (excl. fixtures)
  checked=120  failures=0
byte-identity vs pre-edit baseline (%TEMP%\opencode\m8-baseline\run1.json + baseline-report.md):
  scan --json output (normalize.js drops duration/timestamp + autograd trend
  symbol/direction/summary) ......... NORMALIZED-IDENTICAL   (run1 → run4, post-suite)
  markdown report (Scan Date/Timestamp/Duration lines excluded) ... IDENTICAL
manual bin proofs (cmd /c, UTF-8 redirection — PowerShell > is UTF-16):
  clean demo dir --vision ............ VERIFIED card + report section, exit from scan findings only
  tampered dataset byte --vision ..... INTEGRITY VIOLATION, verdict forced FAIL
                                       ("VisionGuard integrity violation: dataset dimension ..."), exit 1,
                                       1 merged VG finding (tool visionguard)
  same project without --vision ...... zero "VisionGuard" bytes in report and terminal
  storeless project --vision ......... INCOMPLETE attached, no forced verdict, exit unchanged
  hostile store (manifests/dataset is a file) --vision --json
                                       exit 2, stderr message, stdout JSON still parses
mtime audit: session wrote visionguard/{assurance,findings,index}.js (new),
  tests/unit/visionguard/{verdict,assurance,integration}.test.js (new),
  the five §2 sanctioned seams (schema.js, commands.js, bin/codesentry.js,
  report.js, formatter.js) and this log — nothing else
```

### Self-review findings fixed before sign-off

1. **`worstStatus` tie assertion wrong** — `UNSIGNED` and `UNANCHORED` share rank 2, so first-wins keeps `UNANCHORED`; the test initially expected `UNSIGNED` and was corrected to the module's documented behavior before running.
2. **Terminal card truncates the forced message** — the color card wraps at 76 cols and cut `VisionGuard integrity violation…`; the assertion was made branch-agnostic (substrings present in both plain and color output) while the full message remains asserted on `result.verdict.message` and in the report markdown.
3. **Adapter failure was silent under `--json`** — review found `printError` already writes stderr unconditionally, so the `!jsonMode` guard was narrowed to the cosmetic blank line only; hostile-store proof added (exit 2 + stderr + valid JSON).
4. **Facade test authorization mismatch** — the test recorded a `preprocess` op while registering `alice` with only `curate_dataset`; corrected to `['curate_dataset','preprocess']` before the first run (unauthorized path still covered by the `train` rejection).
5. **UTF-16 baseline artifact** — `run1.norm.json` from the baseline capture was PowerShell-encoded; the comparison was redone by piping `normalize.js` through `cmd /c >` (UTF-8) so byte-identity compares like with like.

### Performance / debt

- `runAssurance` on the demo store ≈ 140–530 ms per call (12 scenario copies in `assurance.test.js` total 6.2 s including copy I/O); `scan()`+adapter on the demo dir < 100 ms for the adapter step. Well inside any sane budget.
- Debt: (a) per-record `verifyInference` re-reads `provenance.log` once per record — O(records × log size); batch if M11 profiling needs it. (b) `reportToFindings` dedupes by CodeSentry finding id, so two VG findings with identical file+rule+line collapse to one (hash-derived ids). (c) No automated test spawns `bin/codesentry.js` (no pre-existing test does either) — bin wiring is covered by the five manual proofs above. (d) The demo script's local `overallVerdict` duplication (M7 debt) now has a canonical implementation in `assurance.js` but the demo was left untouched.
- **No new dependencies, no comments in code, core scanner modules untouched.**

**Is this milestone genuinely complete and safe to build upon? — YES.**
Evidence: 49 new tests, 0 failures, covering the exact §9/§11/§12 M8 requirements (seams inert by default with byte-identity proven in both directions; verified store → VERIFIED attach with core signals untouched; every tamper class → dimension FAIL → forced verdict + exit 1; INCOMPLETE/`--require-verified` exit semantics; six-dimension report and terminal rendering with guarded absence; risk-graph injection with summary consistency; facade lifecycle + lineage); full suite `714/695/3` with the identical 3 pre-existing failures at identical locations; `node --check` clean on 120 files; five self-review items found and fixed.

---

## M9 — VisionGuard CLI `vision` command group

**Status:** PASS

### What shipped

- **New `CodeSentry/src/visionguard/cli.js`** — `runVisionCli(argv, io, {root})` implementing all ten §11.2 subcommands: `init`, `register-data`, `verify-data`, `register-model`, `verify-model`, `record-pipeline`, `record-inference`, `verify-output`, `provenance`, `verify`; plus `parseVisionArgs` / `usageText` exports. Human output renders the §8.1 six-row table with per-dimension detail, findings and an actionable next step; `--json` emits the single §11.3 payload `{schema_version, command, overall, dimensions, details, findings, anchored}` with exact key order.
- **Parser seam** — `commands.js`: `COMMANDS.VISION`, early `parse()` branch returning `{command:'vision', visionArgs: args.slice(1)}` before option parsing (so `--json`, `--store`, `.` etc. pass through verbatim), `getHelp()` command + example lines.
- **Dispatch seam** — `bin/codesentry.js`: after the demo block, builds an OutputHandler from `visionArgs.includes('--json')`, runs `runVisionCli`, `process.exit(code)`.
- **Facade seams** — `provenance.registerContributor` now accepts `options.keyFile` (imports an existing PKCS#8 key: load → derive spki → keyId; skips `savePrivateKey`; only unlinks *generated* keys on failure); `index.js`: `state.keyFile` from constructor options, `init()` passes `keyFile` and returns `key_file`, new `recordArtifact()` method; `assurance.js` exports `listManifestRefs`.
- **New `tests/unit/visionguard/cli.test.js`** — 75 tests (parser seam, usage matrix, every subcommand's happy/usage/failure paths, tamper → exit 1, unregistered → exit 3, storeless matrix, anchor conflict/mismatch/match, payload key-order contract, JSON error payloads, flag-before-subcommand, `--store` override).

### Design decisions

1. **Exit codes** — `0` success / `VERIFIED`; `1` integrity violation (also `--require-verified` on `INCOMPLETE`); `2` usage (every `UsageError`, plus `VG_PATH_*`); `3` incomplete (`VG_NOT_REGISTERED`, any non-`PASS`/non-`FAIL` verdict, lineage miss); `4` other `VgError`/unexpected. Usage errors always print `Error: …` + `Run "codesentry vision --help" for usage.` to stderr, even under `--json`.
2. **Error payloads** — operational `VgError` under `--json` becomes a full payload on stdout with `overall: 'INCOMPLETE'` (for `VG_NOT_REGISTERED`) or `'ERROR'` and `details.error = {code, message}`; human mode prints `Error [CODE]: message` on stderr. Non-verify overalls: `OK` (init/provenance), `REGISTERED`, `RECORDED`; single-dimension `verify-*` derive `PASS→VERIFIED`, `FAIL→INTEGRITY VIOLATION`, else `INCOMPLETE`.
3. **Argument parsing** — flags allowed anywhere, first positional is the subcommand; per-subcommand flag whitelist (`ALLOWED`) and positional caps; unknown flag / missing value / excess positional / wrong-for-subcommand flag → exit 2. `--help`/`-h`/`vision help` print usage and exit 0.
4. **Actor & key resolution** — explicit `--actor`/`--key-file` preferred; default actor = sole registered contributor under `<store>/keys/*` (0 → usage "run init first", >1 → usage listing names); default key = sole `~/.codesentry/visionguard/keys/<name>/*.key` (0 or >1 → usage asking for `--key-file`). Non-TTY `init` requires `--actor` **and** `--key-file`; the interactive prompt only fires on TTY without `--json`.
5. **`init --key-file` imports rather than generates** — the imported key is registered as the contributor's key and never deleted on a later registration failure; `details.key_file` reports the absolute path used.
6. **Signing responsibilities** — `register-data` signs a `dataset/<name>@<version>` binding via `recordArtifact` so the dataset dimension can reach `signed_binding: true`; `register-model` is unsigned by design (actor carries the store `key_id`); `record-pipeline` writes only its manifest (M5 design — nothing enters the log); `record-inference` uses the current log head as `parents`.
7. **`verify-*` never pre-checks artifact existence** — a missing directory is simply omitted from the request so assurance falls through to locate and returns `FAIL` (exit 1); hints (`dataset.path`, `model.path`) are only passed when the path exists (`walkDataset` throws `VG_UNREADABLE` on a missing root). Unregistered targets fail earlier with `VG_NOT_REGISTERED` → exit 3.
8. **`verify-model <file|id>` resolution** — exact hash match → target + hint; else basename-minus-ext id match (existing file → hint; otherwise locate); else registered id; else path-looking argument (single model); else `VG_NOT_REGISTERED`. A tampered file named like its registered id therefore reports `INTEGRITY VIOLATION` (1), while an unrelated file reports `NOT_REGISTERED` (3).
9. **`provenance` semantics** — no flags: log summary, exit 0; `--verify`: chain check using the auto/env anchor only (§11.2 gives provenance no anchor flags), unanchored → `INCOMPLETE` → exit 3 (§8.2: `UNANCHORED` is never `VERIFIED`); `--artifact` miss → exit 3; exit precedence `VIOLATION > INCOMPLETE > 0`, and a lineage miss downgrades a `VERIFIED` overall to `INCOMPLETE` so payload and exit code agree; `--graph` embeds the full `{artifacts, contributors, trusts, derivedFrom}` arrays.
10. **Anchor handling in `verify`** — `--expected-head` and `--anchor-file` are mutually exclusive (exit 2); otherwise assurance resolves `VG_EXPECTED_HEAD` / `.visionguard/anchors/head.txt` internally; the committed anchor file is user-managed (nothing in src writes it).

### Evidence

```
manual bin smoke (cmd sequences from a temp project + a runDemo copy):
  vision --help ........................ exit 0, full usage; bare "vision" .... exit 2
  init --actor+--key-file --json ....... OK payload, store created, key imported
  register-data / verify-data ........... REGISTERED → VERIFIED (0);
                                          tampered dataset → FAIL findings → exit 1
  register-model (sniffed onnx) ......... REGISTERED; verify-model id/file → 0;
                                          tampered model → id → 1, basename file → 1,
                                          unrelated name → 3, storeless → 3
  record-pipeline / record-inference .... RECORDED with resolved
                                          model/clf@1.0.0 + pipeline/htp@1.0.0 refs;
                                          unregistered model → payload INCOMPLETE, exit 3
  verify-output ......................... PASS (0) / unknown ref (3) / tampered (1)
  verify (full, tampered demo) .......... §8.1 table + Overall: INTEGRITY VIOLATION, exit 1;
                                          clean demo → VERIFIED, anchored: yes, exit 0;
                                          storeless → all NOT_CHECKED, exit 3
  provenance ............................ summary (0), --verify unanchored (3),
                                          --artifact hit (0) / miss (3), --graph (0),
                                          --expected-head bogus → VG-PROV finding, exit 1
  usage matrix .......................... unknown flag / missing value / excess positional /
                                          wrong-for-sub flag / bad --format / missing file /
                                          missing actor or key-file → all exit 2 with stderr
                                          guidance; invalid key file → VG_KEY_UNKNOWN, exit 4
regression:
  node scripts/test-runner.js all ....... 789 tests / 770 pass / 3 fail / 16 skip
                                          (= 714+75 / 695+75; identical 3 pre-existing
                                          failures at pipeline.test.js:203, auth.test.js:160,
                                          auth.test.js:174)
  node --test tests/unit/visionguard .... 464 / 448 pass / 0 fail / 16 skip (= 390+75)
  node --check sweep .................... 123 files, 0 failures
mtime audit: session wrote visionguard/cli.js (new),
  tests/unit/visionguard/cli.test.js (new), the three sanctioned seams
  (commands.js, bin/codesentry.js, + provenance/index/assurance facade edits)
  and this log — nothing else; temp smoke dirs cleaned
```

### Self-review findings fixed before sign-off

1. **`lineage()` return shape misread** — first implementation mapped `entry.record` over the result, but `index.js` returns `chain.map(e => e.record)` (raw records); the chain silently came back empty under filtering. Reverted to record mapping; test asserts ancestor ordering (oldest first).
2. **`verify-model <basename>` gap** — the basename-id fallback existed only in the is-a-file branch, so a tampered file whose path did not resolve (relative to root) returned `NOT_REGISTERED` (3) instead of `FAIL` (1); the fallback was added to the non-file branch too.
3. **Provenance human noise** — `--artifact` / `--graph`-only runs printed a misleading "No provenance summary available." header; the summary block is now restricted to flag-less invocations (test asserts the string is absent).
4. **Payload/exit disagreement** — `provenance --verify --artifact <miss>` reported `VERIFIED` while exiting 3; a `VERIFIED→INCOMPLETE` downgrade now applies whenever a lineage miss forces the exit, keeping the contract consistent (test updated to expect `INCOMPLETE` with `dimensions.provenance.status: PASS`).
5. **Draft-test sloppiness** — a self-equality hash assertion, a dead ternary, and a wrong lineage `kind` expectation (chain[0] is the contributor registration, not the binding) were cleaned up before sign-off.

### Performance / debt

- `runVisionCli` adds only `node:fs/path/crypto/readline` on top of the existing facade; command latency is dominated by `runAssurance` (M7 ≈ 140–530 ms) — full `vision verify` on a demo copy ≈ 0.2–0.4 s, the 75-test CLI suite ≈ 7 s including one `runDemo` fixture build.
- Debt: (a) no automated test spawns `bin/codesentry.js` (consistent with the repo — dispatch covered by manual smoke above); (b) `verify-data` with multiple registered datasets and no `--name` (aggregate path) is implemented but only indirectly exercised; (c) interactive TTY `init` prompt path is untestable in CI — the non-TTY branch is fully covered; (d) `verify` payload omits the chain head — `vision provenance` is the head-discovery surface; (e) `--expected-head` on a value that itself starts with `-` is consumed as the value (standard parser behavior).
- **No new dependencies, no comments in new code (including new blocks in existing files), core scanner untouched.**

**Is this milestone genuinely complete and safe to build upon? — YES.**
Evidence: 75 new tests, 0 failures, covering the §11.2 command set, §11.3 payload contract, §11.4 exit-code map and §11.5 parser integration (usage matrix, tamper → 1, unregistered → 3, storeless → 3, anchor semantics, JSON key-order equality, error payloads); full suite `789/770/3` with the identical 3 pre-existing failures at identical locations; `node --check` clean on 123 files; a manual bin smoke covering every subcommand and exit code; five self-review items found and fixed.

---

## M10 — Security hardening

**Status:** PASS

### What shipped

- **Attack-matrix e2e suite** — new `CodeSentry/tests/unit/visionguard/security.test.js` (19 tests, ~7 s) chaining every §12 M10 class through the real surfaces (`runVisionCli`, facade, spawned `bin/codesentry.js` children):
  - **register path guards (3)** — `register-data` outside the project root / the root itself (`.`), `register-model` outside the root → exit 2;
  - **`--params` JSON bombs (3)** — depth-64 nest (parses, then canonical depth cap rejects), 40 000-deep stack overflow, 9 MiB oversized file → exit 2 before any parse work;
  - **hostile manifest paths (3)** — `../escape.png`, `C:/Windows/escape.png`, control char (U+0007), bidi override (U+202E), 300-char component → dataset `FAIL` → exit 1, escaped path never created;
  - **provenance attacks on demo copies (5)** — log-tail rollback behind a live anchor → `FAIL VG-PROV-008` exit 1; same rollback with anchor deleted → `UNANCHORED`/`INCOMPLETE` exit 3; signature stripping (anchor still *matches*, since `record_hash` excludes signatures) → `UNSIGNED`/`INCOMPLETE` exit 3 with `VG-PROV-009`; substituted registered key (attacker DER, victim `key_id`, re-hashed and re-signed) → `FAIL VG-PROV-003` exit 1; replayed log record → `FAIL VG-PROV-006` exit 1 — none of them ever reports `VERIFIED`;
  - **TOCTOU (2)** — `assertStableStats` drift on size/ino/dev/mtime → `VG_RACE_DETECTED`; `readSniffHead` stat drift vs the hash-time stat → `VG_RACE_DETECTED`;
  - **resource exhaustion (2)** — facade `limits.maxFiles`/`maxFileSize` → `VG_LIMIT_FILE_COUNT` / `VG_LIMIT_FILE_SIZE`;
  - **concurrent verify+register (1)** — two spawned `vision register-data` processes in parallel → both exit 0, both datasets verify `PASS`, chain never `FAIL`.
- **Product fix 1 — `cli.js jsonFlag` parses with `parseCanonical`** (`maxBytes` 8 MiB, `maxDepth` 32) behind a single `statSync` snapshot (size pre-check before reading): depth-64 files that previously slipped past `JSON.parse` and exploded later at exit 4, and stack-overflow `RangeError`s, are now uniform usage errors → exit 2 naming the flag; oversized files are rejected without being read.
- **Product fix 2 — `register-data` / `register-model` inside-root guards** — a manifest pointing outside the root is unlocatable on every later verify (permanent `FAIL` foot-gun); both now reject `..`, absolute, cross-drive and root-itself targets with `UsageError` → exit 2, before actor/key resolution.
- **Product fix 3 — cross-drive hardening of `fileRef` / `pipelineFileRef`** — `path.relative` across drives returns an absolute path that does *not* start with `..`; added `path.isAbsolute(rel)` so `record-inference` I/O refs and `--code/--deps/--preprocess` cannot smuggle `D:\…` through the in-root checks.

### Design decisions

1. **Write/register operations are root-bound; read-only lookups are not** — `register-*` must produce manifests locatable from the root (guards added), while `verify-*` positional hints, `--params`/`--runtime` input files and `normalizeArtifactTarget` lookups stay unrestricted: they only read, and the params surface is now byte+depth capped instead.
2. **Depth bombs surface as usage errors, not exit 4** — a user-supplied file failing canonical parsing is an input problem: `jsonFlag` maps every `parseCanonical` failure (syntax, 8 MiB cap, depth > 32, parser `RangeError`) to `UsageError` → exit 2 with the flag name in the message.
3. **Rollback verdicts split on anchor presence, both provably non-VERIFIED** — anchored: `FAIL VG-PROV-008` (1); anchor removed: `UNANCHORED` → `INCOMPLETE` (3); signature stripping keeps the anchor matching yet is demoted to `UNSIGNED` → `INCOMPLETE` — stripping can never mint a `VERIFIED`.
4. **The substitution e2e forges the real adversary** — attacker DER under the victim `key_id` with recomputed `record_hash` + signature (the provenance-unit adversary), not a sloppy swap, proving detection end-to-end at exit 1 / `VG-PROV-003`.
5. **Concurrency asserts safety, not scheduling** — both children must exit 0 (lock with retry), both datasets must verify `PASS`, chain must never `FAIL`; ordering between processes is intentionally unconstrained.
6. **TOCTOU needed no product change, only proof** — §5.2 checks (fstat before/after + path re-stat + model fd-vs-hash stat) existed but had zero tests; they are now covered at both seams.
7. **Long-filename cap proven via manifest, not the filesystem** — win32 cannot create 300-char components, so the length class is exercised through the manifest path gate (`normalizeRelPath`), same as traversal/control/bidi.

### Evidence

```
node --test tests/unit/visionguard/security.test.js
  ................................. 19 tests / 19 pass / 0 fail (~7.3 s)
  register guards 3, params bombs 3, hostile manifest paths 3,
  provenance attacks 5, races & exhaustion 5
regression:
  node scripts/test-runner.js all ....... 808 tests / 789 pass / 3 fail / 16 skip
                                           (= 789+19 / 770+19; identical 3 pre-existing
                                           failures at pipeline.test.js:203, auth.test.js:160,
                                           auth.test.js:174)
  node --test tests/unit/visionguard .... 484 / 468 pass / 0 fail / 16 skip
  node --check sweep .................... 123 non-fixture files, 0 failures
                                          (2 excluded fixtures are intentionally malformed)
mtime audit: this session wrote src/visionguard/cli.js (jsonFlag hardening +
  3 guards), tests/unit/visionguard/security.test.js (new) and this log —
  nothing else
```

### Self-review findings fixed before sign-off

1. **`jsonFlag` stat race** — `existsSync` → `statSync` → second `statSync` left a window where a vanishing file threw raw `ENOENT` (exit 4); replaced with one `try { statSync } catch` whose size feeds the cap — same snapshot, one syscall.
2. **Cross-drive hole in existing in-root checks** — `fileRef`/`pipelineFileRef` only tested `rel.startsWith('..')`, but `path.relative('C:\a','D:\b')` returns an absolute path; `path.isAbsolute(rel)` added to both (guards from this milestone use the same form).
3. **Literal control bytes in test source** — the first draft embedded raw U+0007/U+202E characters, corrupting the file write; rewritten with `String.fromCharCode` so the source stays ASCII-clean.

### Performance / debt

- Security suite ≈ 7.3 s (one `runDemo`, five scenario copies, two spawned node processes ≈ 1.9 s of it); VG suite ≈ 26–39 s; full 808-test run within the prior envelope. Guard checks are O(1) relative-path tests; `jsonFlag` adds one stat plus a canonical depth walk over ≤ 8 MiB — no change to hashing/walk hot paths.
- Debt: (a) no new symlink/hardlink e2e — unit rows already cover walk policy escalation/skip (`walk.test`, `manifest.test`) and hash identity includes `ino`/`dev`, while win32 link creation needs privilege (existing graceful-skip pattern kept); (b) `--params`/`--runtime` may point outside the root by design (read-only, now capped); (c) `normalizeArtifactTarget` returns a slashified absolute string for outside-root lookups — display/match only, no record or filesystem effect; (d) cross-drive guard branches untested (single-drive machine); (e) the spawned-children test depends on the default lock timeout covering slow CI starts (retry loop; zero flakes observed).
- **No new dependencies, no comments in new code (including new blocks in existing files), core scanner untouched.**

**Is this milestone genuinely complete and safe to build upon? — YES.**
Evidence: 19 new e2e tests covering every §12 M10 class (path traversal, long/control/bidi names, manifest tamper, anchored + unanchored rollback, oversized inputs, JSON depth bombs, signature stripping, key substitution, replay, concurrent register+verify, resource exhaustion, TOCTOU) plus three product hardenings; full suite `808/789/3` with the identical 3 pre-existing failures at identical locations; VG suite `0 fail`; `node --check` clean; three self-review items found and fixed.

---

## M11 — Performance

**Status:** PASS

### What shipped

- **Performance suite** — new `CodeSentry/tests/unit/visionguard/performance.test.js` (5 tests) covering the §12 M11 row ("100k small files, few huge files, repeated verification, memory ceiling, no double hashing"):
  - **Always-on "single-pass hashing" (3 tests, 5.2 s):** (a) 2 000-file corpus under a `fs.openSync`/`readSync`/`closeSync` spy (read-only tracked via `flags & 0o3 === 0`) — every dataset file read **exactly once per register and exactly once per verify** (`bytesRead === size` for all 2 000 files), register heap growth < 256 MiB; (b) 4 MiB ONNX model + `record-pipeline` + `record-inference`, two full `runAssurance` rounds under the spy — model bytes read < 1.5× size per round (this failed at 2× before the reuse fixes), model entry `located=true`, dimension never `FAIL`; (c) demo copy — `vision verify --json` ×3 → identical scrubbed payloads, `.visionguard` store snapshot (`rel:size:mtimeMs`) untouched after every run.
  - **Heavy benchmarks gated by `VG_PERF=1` (2 tests, skipped otherwise):** *flood* — 100 000 flat files registered and verified twice; budgets create < 900 s / register < 300 s / verify < 300 s / re-verify < 300 s, manifest bytes strictly inside the (8 MiB, 32 MiB) window, `diff.unchanged === 100000`, second verify deep-equals first, heap growth < 768 MiB, all timings via `t.diagnostic`. *huge* — 3 × 512 MiB files via `fs.truncate` (graceful skip if the filesystem refuses), `total_bytes` exact, register/verify < 180 s each, heap < 128 MiB.
- **Spec amendment — `maxManifestBytes` 8 MiB → 32 MiB** (`src/visionguard/limits.js:12`, assertion at `tests/unit/visionguard/limits.test.js:32`): the 100 000-file target serializes to a **14 MiB** manifest (measured by the gated run), so the old 8 MiB cap made the flagship M11 scenario unregistrable by construction; 32 MiB keeps a hard parse bound with ~2.3× headroom. Documented in design.md §5.1 (line 307) and the §5.5 rationale (lines 352–353).
- **No-double-hashing fixes — one pass per file per operation:**
  - `model.js` — module-local `reuseHashed(filePath, expected)` (line 327): bigint `lstat` revalidates `ino`/`dev`/`size`/`mtimeNs` of an earlier `hashFile` result; `registerModel` and `verifyModel` now do `reuseHashed(...) || hashFile(...)`. Every `BigInt(...)` conversion sits inside the `try` — a malformed or stale hint falls back to a full hash instead of throwing.
  - `assurance.js` — `locateModelFile` returns `{abs, hashed}` on sha-exact match (line 204) or `{abs, hashed: null}` on the same-size/basename fallbacks (209/213); `modelHintHashed` (539) taken from `options.model.hashed`; `verifyModel` receives `hashed: located.hashed` (573); new `modelShaByKey` map (462) fed from `verification.actual.sha256` (579); the inference loop passes `modelSha256` (674–680).
  - `inference.js` — `verifyInference` compares `options.modelSha256` directly when present (line 311, zero rehash), else falls back to `hashCheckedFile(modelPath)` per record (317).
  - `index.js` — facade `registerModel` forwards `hashed` (line 99); facade `verifyModel` deliberately does **not** (107), so standalone callers always get exactly one hash.
  - `cli.js` — `cmdRegisterModel` passes its sniff-time `hashFile` result into `vg.registerModel` (764); `cmdVerifyModel` tracks `hintHashed` at both `hint = abs` sites (820, 830) and passes it into `runAssurance({model:{…, hashed}})` (874).

### Design decisions

1. **The cap amendment is a spec change, not a tuning knob** — §12's M11 row mandates 100 000 files; a manifest bound below the target's own serialized size would make the milestone untestable. 32 MiB still bounds worst-case parse memory to one canonical-JSON document ≤ 32 MiB.
2. **Reuse is stat-gated, never trust-gated** — a hint is accepted only when bigint `lstat` matches `ino/dev/size/mtimeNs`; `readSniffHead` then re-opens the file and re-checks fstat before/after **and** against the same expected values (model.js:224–235), so the widened window between the CLI's hash and assurance's verify still trips `VG_RACE_DETECTED` on drift.
3. **A hint is honored only when exactly one model is registered** (`assurance.js:535` requires `modelRefs.length === 1`) — with 2+ registered models a single path hint cannot be attributed safely, so hint+hash are dropped and every model is located and hashed normally. Conservative by design.
4. **Basename/same-size fallback detects changes without a second read** — `verify-model <tampered>` reuses the just-computed hash and reports `VG-MODEL-001 content changed` from it (pinned by `cli.test.js:447`).
5. **A null/absent model sha falls back to the old per-record `hashCheckedFile`** — a failed or empty model verification can never satisfy an inference record with a stale hash.
6. **Always-on vs gated split** — the three behavioural proofs run in seconds on every CI run; only the 100 000-file and 512 MiB corpora require `VG_PERF=1`.

### Evidence

```
cmd /c "set VG_PERF=1&& node --test tests/unit/visionguard/performance.test.js > logs\perf-gated.txt 2>&1"
  tests 5 / pass 5 / fail 0 / skipped 0        duration_ms 475427
  flood: create=84182ms register=102332ms verify=117836ms verify2=108146ms
         heapGrowth=79MiB manifest=14MiB       (budgets 900/300/300/300 s, heap < 768 MiB)
  huge:  register=2625ms verify=1718ms heapGrowth=1MiB   (budgets 180/180 s, heap < 128 MiB)
  always-on suite 5182ms (corpus 4853ms / model-once 107ms / repeat-verify 219ms)
regression (VG_PERF unset):
  node scripts/test-runner.js all ....... 813 tests / 792 pass / 3 fail / 18 skip
                                           (duration_ms 27340; the 3 failures are the identical
                                           pre-existing trio at pipeline.test.js:203,
                                           auth.test.js:160, auth.test.js:174)
  node --test tests/unit/visionguard .... 489 / 471 pass / 0 fail / 18 skip (19.8 s)
  node --check sweep .................... 125 non-fixture files, 0 failures
  evidence files: logs/perf-gated.txt, logs/m11-full.txt, logs/m11-vg.txt
mtime audit: the M11 milestone wrote src/visionguard/{limits,model,assurance,inference,index,cli}.js,
  tests/unit/visionguard/{limits,performance}.test.js and docs/visionguard/design.md (§5.1/§5.5),
  all stamped 10/3 01:58–02:05; this continuation session wrote only logs/*.txt and this log
```

### Self-review findings fixed before sign-off

1. **Void benchmark evidence** — the earlier gated capture produced a 0-byte `perf-gated.txt` and no `%TEMP%\vg-perf-*` directory, proving node never launched (PowerShell-style env prefix / no canary). Re-ran through `cmd /c "set VG_PERF=1&& (echo CANARY …) > file"` with a 45-minute timeout; the canary line plus `skipped 0` prove `VG_PERF` reached the test process.
2. **Test harness bug (fixed during development)** — `record-pipeline`/`record-inference` in the model-once test exited 2 until `--key-file key.file` was supplied.
3. **Nine hostile-review items re-verified against the code, no further fixes needed** — `readSniffHead` revalidates via fstat (model.js:224–235); hint gated on `modelRefs.length===1` (assurance.js:535); basename fallback flags changed files through the reused hash (cli.js:824–831); `modelShaByKey=null` → per-record `hashCheckedFile` fallback (assurance.js:680 → inference.js:317); facade `verifyModel` still single-hashes (index.js:107); `locateModelFile` has exactly one caller (assurance.js:557); `hashFile` returns `ino/dev/mtimeNs` as strings with every `BigInt(str)` conversion inside `try` (hash.js:136–138, model.js:329–341); spies restore in `finally` (performance.test.js:182/194/251); `cli.js`'s `hashFile(abs, {})` uses `DEFAULT_LIMITS` — pre-existing sniff pattern, unchanged this milestone.

### Performance / debt

- Gated: flood ≈ 412.5 s end-to-end (create 84 s + register 102 s + verify 118 s + re-verify 108 s) at 79 MiB heap growth against a 768 MiB ceiling; huge files 2.6 s / 1.7 s at 1 MiB. Always-on 5.2 s; VG suite 19.8 s; full 813-test run 27.3 s of test time (file-parallel).
- The 14 MiB flood manifest confirms both the amendment (old cap would reject it) and the new bound (32 MiB holds with headroom).
- **M7 provenance debt carried:** `appendRecord` re-reads and re-parses the **entire** provenance log on every append (provenance.js:386–387 — full chain validation plus duplicate-`record_hash` scan before each write), making chain building O(n²) in record count; bounded by `maxLogBytes` (512 MiB), not exercised by the M11 benchmarks (they register/verify, never append), and deferred until a benchmark or a real chain size shows it mattering. Related: `listProjectFiles` caps candidate enumeration at `maxFiles` (100 000, assurance.js:144) — pre-existing guard, reached only by projects already at the register limit.
- **No new dependencies, no comments in new or edited code (grep-verified across `src/visionguard` and the new test), tests carry no 'use strict' header.**

**Is this milestone genuinely complete and safe to build upon? — YES.**
Evidence: 5 new tests — 3 always-on behavioural proofs (byte-level single-pass reads for datasets, model hashed once per verification run, repeated verification byte-identical with an untouched store) plus 2 gated benchmarks — all green under `VG_PERF=1` with every budget met (100 000 files registered and verified twice at 102 s/118 s/108 s, 14 MiB manifest inside the amended cap, 79 MiB heap vs 768 MiB; 3 × 512 MiB at 2.6 s/1.7 s and 1 MiB heap); the §12 M11 row is fully exercised; full suite `813/792/3` with the identical 3 pre-existing failures at identical locations; VG suite `0 fail`; `node --check` clean on 125 files; three self-review items recorded.

---

## M12 — Full regression / release verification

**Status:** PASS

### What shipped

- **User-facing-docs gap closed (the release finding)** — design §13 states its eight known limitations "must appear in user-facing docs", but neither README mentioned VisionGuard at all (grep count 0). Both `CodeSentry/README.md` (the npm-shipped readme, per `package.json` `files`) and the root `README.md` (GitHub landing) now carry:
  - **Key Capability #9 — VisionGuard: Tamper-Evident ML Pipeline Provenance**: hash-backed artifact identity (datasets/models/pipeline/inference, Merkle-rooted manifests), signed Ed25519 provenance chain, one anchored six-dimension verdict, design.md link;
  - a **VisionGuard block in the CLI usage examples** (`init → register-data → register-model → record-pipeline → record-inference → verify`) with the key semantics as implemented: interactive first run generates the keypair; CI/non-TTY `init` requires an existing `--key-file`; signing commands auto-discover the actor's key;
  - **"VisionGuard Known Limitations (by design)"** — all eight §13 items plus the `vision verify` exit-code map (0/1/2/3/4);
  - stale headline test count refreshed (97 tests/30 suites → 813/165).
- **Full release regression re-run from scratch** (three clean evidence files: `logs/m12-full.txt`, `logs/m12-vg.txt`, plus the M11 `logs/perf-gated.txt`): counts match the bar exactly.
- **Real-CLI end-to-end smoke** through `node bin/codesentry.js` in a throwaway project (temp dir, generated Ed25519 key, CSV dataset, 16-byte ONNX-magic model), asserting ten commands against their §11.4 exit codes.

### Design decisions

1. **Both READMEs, not just the shipped one** — they are near-identical copies (repo convention) and both are user-facing; updating only the package readme would leave the GitHub landing contradicting the release.
2. **Document key handling as the code behaves, not as the help text implies** — `vision init` only reaches the keypair-generation path (`provenance.js:504-506`) when interactive; non-TTY requires a pre-existing `--key-file` (`cli.js:584-585`); `resolveKeyFile` auto-discovers exactly one `<contributor>` key or demands an explicit `--key-file` (`cli.js:337-357`).
3. **Release asserts parity, not a false green** — the 3 pre-existing failures (documented as baseline since the earliest checkpoint, in untouched core/auth tests) must stay byte-identical in location and assertion; "fixing" them would mean editing unrelated core code outside the VisionGuard scope.

### Evidence

```
node scripts/test-runner.js all ....... 813 tests / 792 pass / 3 fail / 18 skip (28.2 s, logs/m12-full.txt)
                                         3 failures identical baseline: pipeline.test.js:203,
                                         auth.test.js:160, auth.test.js:174
node --test tests/unit/visionguard .... 489 / 471 pass / 0 fail / 18 skip (20.5 s, logs/m12-vg.txt)
node --check sweep .................... 125 non-fixture files, 0 failures
gated performance (M11 evidence) ....... 5/5 pass under VG_PERF=1 (logs/perf-gated.txt)
dependencies .......................... package.json untouched: dotenv ^17.4.2 is the only dependency
comment audit .......................... src/visionguard/* and session tests: 0 comments, no 'use strict'
bin smoke (10/10 expected codes) ....... vision badcmd → 2; vision --help → 0; init non-TTY w/o key → 2;
                                         init --key-file → 0; register-data → 0; register-model → 0;
                                         verify-data signed binding → 0; verify fresh store → 3
                                         (INCOMPLETE/unanchored); verify after dataset byte flip → 1
                                         (INTEGRITY VIOLATION, VG-DATA-001); verify storeless → 3
README docs ............................ capability #9 + CLI examples + 8 limitations + exit codes in both
                                         READMEs; headline count 97/30 → 813/165
mtime audit: this milestone wrote CodeSentry/README.md, root README.md, logs/m12-*.txt and this log
```

### Self-review findings fixed before sign-off

1. **The first README draft would have failed for real users** — it showed `vision init --actor alice --key-file alice.key` on every line, but non-TTY init *requires* a pre-existing key file and no CLI keygen command exists; rewritten to the interactive-generation flow with an explicit CI note, matching `cli.js:571-612` / `cli.js:337-357`.
2. **Stale headline test count in both READMEs** ("97 tests across 30 suites") — refreshed to the true release numbers; flagged so M13 updates it again after adding the scenario tests.
3. **`anchored` on a fresh store is `null`, not `false`** — the smoke confirmed the documented semantics (no anchor supplied ⇒ "no anchor supplied", overall INCOMPLETE/exit 3); no code change required.

### Performance / debt

- No product code changed this milestone — documentation, smoke script (outside the repo, in temp) and logs only; regression timings inside the M11 envelope (full 28.2 s, VG 20.5 s, file-parallel).
- Debt: (a) the two READMEs remain hand-duplicated — divergence risk on any future doc edit; (b) exit 4 (internal-error path) is covered by unit error mapping but was deliberately not provoked in the bin smoke via fault injection; (c) the 3 baseline failures still keep the suite from a literally-green run — pre-VisionGuard, unrelated core/auth code.
- **No new dependencies, no comments in new or edited code.**

**Is this milestone genuinely complete and safe to build upon? — YES.**
Evidence: full suite `813/792/3/18` and VG suite `489/471/0/18` with the identical 3 pre-existing failures at identical locations; `node --check` clean on 125 files; the zero-new-dependency constraint re-verified against `package.json`; a 10-command real-CLI smoke proving the §11.4 exit-code map end-to-end (2/0/2/0/0/0/0/3/1/3); the design-§13 user-facing-docs requirement satisfied in both READMEs; M11's gated performance evidence green.

---

## M13 — SIH demonstration

**Status:** PASS

### What shipped

- **Scenario suite A–F**: new `tests/integration/visionguard-pipeline.test.js` (6 tests / 1 suite), the release demonstration of the whole VisionGuard chain. One shared `demo.runDemo` base, one `fs.cpSync` copy per test, **exactly one tamper per test**, asserting exit code + overall verdict + targeted dimension + **exact rule ID**:
  - **A (clean)** — pristine demo through the **real `bin/codesentry.js` spawn**: exit 0, `VERIFIED`, `anchored: true`, six dimensions `PASS`, empty findings, store present and valid;
  - **B (dataset)** — one byte flipped in `dataset/circle/00.png`: exit 1, `INTEGRITY VIOLATION`, dataset `FAIL`, `VG-DATA-001`;
  - **C (model)** — one byte flipped in `model/<MODEL_ID>.safetensors`: exit 1, model `FAIL`, `VG-MODEL-001`;
  - **D (pipeline)** — one line appended to `pipeline.js`: exit 1, pipeline `FAIL`, `VG-PIPE-001`;
  - **E (provenance)** — last provenance-log line removed **with the live anchor asserted present first**: exit 1, provenance `FAIL`, `VG-PROV-008`;
  - **F (output)** — one byte flipped in `outputs/prediction.json`: exit 1, output `FAIL`, `VG-OUT-001`.
- README headline counts refreshed 813/165 → **819/166** in both READMEs (the M12 self-review follow-through).

### Design decisions

1. **Scenarios derived from design.md as approved** — A covers the documented clean path (§13's "bounded integrity evidence … never a proof of quality" starts from a true baseline); B–F each attack one of the tamper classes the design promises to catch, one per dimension family (inference-input tampering is already pinned by `assurance.test.js:160`, so F uses the output dimension to complete the six-dimension sweep).
2. **Hybrid execution per the approved convention** — A spawns the real bin (full CLI → `--json` → exit-code path); B–F call in-process `runVisionCli` exactly like `security.test.js`, which is what allows exact rule assertions without six extra process spawns (~1.5 s total).
3. **Exact rule IDs, not prefix matches** — every assertion is a pinned ID verified against source (`manifest.js:360`, `model.js:494`, `pipeline.js:506`, `provenance.js:1031`, `inference.js:378`), stronger than the existing `startsWith('VG-…')` unit assertions.
4. **Anchor presence asserted before E's rollback** — proves the scenario runs "behind a live anchor"; if a future demo change stops shipping `.visionguard/anchors/head.txt`, the test fails loudly instead of silently degrading to the exit-3 unanchored path.

### Evidence

```
node --test tests/integration/visionguard-pipeline.test.js ... 6/6 pass, 0 fail (1.99 s)
node scripts/test-runner.js all ........ 819 tests / 166 suites / 798 pass / 3 fail / 18 skip
                                          (32.6 s, logs/m13-full.txt) = M12 counts + exactly +6 tests
                                          3 failures identical baseline: pipeline.test.js:203,
                                          auth.test.js:160, auth.test.js:174
node --check sweep ..................... 126 files, 0 failures (+1 for the new test file)
comment audit .......................... visionguard-pipeline.test.js: 0 comments, no 'use strict'
README counts ......................... both READMEs 813/165 → 819/166
package.json ........................... untouched (dotenv ^17.4.2 still the only dependency)
mtime audit: this milestone wrote tests/integration/visionguard-pipeline.test.js, both READMEs,
            logs/m13-full.txt, this log
```

### Self-review findings fixed before sign-off

1. **Temptation to spawn the bin for all six scenarios rejected** — B–F stay in-process per the M10/security.test convention; the bin's full path is already proven by scenario A plus M12's 10-step smoke, so ×6 spawns would buy no coverage.
2. **README counts would have gone stale again** the moment the suite was added — updated in the same milestone, closing M12's self-review finding 2.
3. **E could silently become an unanchored test** if the demo ever stops writing its anchor — fixed by asserting `anchors/head.txt` exists *before* the tamper.

### Performance / debt

- New suite: 2.0 s standalone; full regression 32.6 s vs M12's 28.2 s (file-parallel envelope, +6 tests plus one real bin spawn).
- Debt carried: (a) hand-duplicated READMEs remain divergence-prone; (b) scenario D's tamper is append-only — an in-place byte edit of pipeline code is only covered at unit level; (c) the demo base runs once per suite process and is copy-shared (by design).
- **No new dependencies, no comments in new or edited code.**

**Is this milestone genuinely complete and safe to build upon? — YES.**
Evidence: all six approved scenarios pass `6/6` with exact, source-pinned rule IDs and the required exit codes (A→0, B–F→1); full suite `819/798/3/18` with the identical pre-VisionGuard baseline trio; `node --check` clean on 126 files; `package.json` untouched; READMEs carrying both the §13 limitations (M12) and the true release counts. This closes the M0–M13 program.

---

## M14 — Final acceptance pass (§7/§8)

**Status: PASS**

### What shipped (code)

- `src/visionguard/inference.js` — **expected-vs-actual hashes** (the prompt's scenario-D requirement): the `VG-OUT-001` human detail is now `output file content does not match the recorded hash: expected <sha>, got <sha>`, and both hashes ride the JSON payload as `findings[].expected` / `findings[].actual`; `VG-INFER-001` input-mismatch findings gained the same structured fields (text unchanged).
- `src/visionguard/assurance.js` — `addFinding` gained a 6th `extra` parameter guarded by `FINDING_CONSUMED_KEYS` (`rule`, `severity`, `path`, `detail`, `message`): non-consumed fields (`expected`, `actual`, `line`, …) now survive into `report.findings`; all five loop sites (incl. the provenance merge at :448) pass the source item.
- `tests/integration/visionguard-pipeline.test.js` — scenarios **A–F extended to A–I** (9 tests): **G** edits the middle provenance record via `canonicalJson` → exit 1, `VG-PROV-001` (record's own `record_hash` breaks; chain also reports `VG-PROV-005`), `finding.line === index+1`; **H** flips one signature byte → exit 1, `VG-PROV-002`; **I** rolls back the tail *and* deletes the anchor → exit 3, `INCOMPLETE`, `Provenance: UNANCHORED`, `anchored` asserted `notEqual true` (never `VERIFIED`). F now hashes `outputs/prediction.json` before/after the flip and asserts `hit.expected`/`hit.actual` equal the recorded/computed hashes **and** appear in `detail`.
- `tests/unit/visionguard/inference.test.js` — +3 assertions pinning `expected` = recorded input hash, `actual` = 64-hex and unequal.
- **New `scripts/visionguard-sih.js`** — the §8 one-command demonstration: 9 scenarios A–I, one pristine `runDemo` base, one `fs.cpSync` copy per scenario, **exactly one tamper each** (A: none), every verdict obtained from the **real spawned bin** (`vision verify --json`), verdict table + `--json` + `--out` + `--help`; exit `0` all matched, `1` mismatch, `2` usage, `4` internal. Zero deps (`node:*` only), no comments.
- **New `docs/visionguard/SIH_DEMO.md`** — honesty scope table, prerequisites, one-command runner with captured 9/9 output, clean demo build with captured output, manual per-scenario sequence B–I (each: reset copy → one tamper → verify, with expected exit/verdict/rule), scenario→requirement mapping, cleanup.
- **New `docs/visionguard/DELIVERABLES.md`** — §8's 15 deliverables and §7's 11 acceptance checkboxes, each mapped to artifact + evidence log, plus an evidence index and known-debt list; carries an explicit source note (prompt text not in repo → numbering reconstructed, evidence verbatim).
- Both `README.md`s — headline counts 819/166 → **822/166** and a reproducible-demo pointer line (`node scripts/visionguard-sih.js` → `SIH_DEMO.md`).

### Design decisions recorded this milestone

1. **Hashes go in `detail` *and* as structured fields** — human output renders only `finding.detail` (`cli.js` findingLines), so the scenario-D "expected vs actual" requirement must live in the text; JSON consumers get the same data as `expected`/`actual` without parsing prose. One source, two renderings.
2. **`addFinding` consumed-keys guard** — extras may only fill `undefined` slots, so callers can never clobber `rule`/`severity`/`path`/`detail`/`message`; this is the report-layer analogue of provenance.js's `Object.assign` merge (line 628) with the safety inverted.
3. **Runner spawns the real bin; the suite stays hybrid** — jury-facing evidence must be actual CLI invocations (exit codes included), while the permanent suite keeps M13's in-process convention for exact rule assertions; both assert the same pinned rule IDs, so they cannot drift apart silently.
4. **G/H one-liners take the module path as `process.argv[1]`** — a JS string literal swallows backslashes (`'C:\Users\…'` → `C:Users…`, `MODULE_NOT_FOUND`); the argv form works identically in PowerShell and bash and tolerates spaces in the repo path. Verified end-to-end: G → exit 1 `VG-PROV-001,VG-PROV-005`, H → exit 1 `VG-PROV-002`, log preserved after both.
5. **Scenario I asserts `anchored !== true`, not `=== false`** — `null` means "no anchor supplied", `false` means "supplied but mismatched"; the honesty claim is "never VERIFIED", so the assertion pins the actual contract.
6. **§7/§8 verbatim unrecoverable → reconstruct with a source note** — the prompt exists only in conversation history; `DELIVERABLES.md` labels its numbering as reconstructed while every number, rule ID and log reference is re-runnable.

### Evidence (commands run, counts)

```
node scripts/visionguard-sih.js ........... 9/9 PASS, exit 0 (logs/m14-runner.json)
                                            also: --help → 0, --bogus → 2
node --test tests/integration/visionguard-pipeline.test.js ... 9/9 (within the full run)
node scripts/test-runner.js all ........... 822 tests / 166 suites / 801 pass / 3 fail / 18 skip
                                            (40.8 s, logs/m14-full.txt) = M13 counts + exactly +3 tests
                                            same baseline trio: pipeline.test.js:203,
                                            auth.test.js:160, auth.test.js:174
bin smoke (M12 script, M14 code) .......... 10/10 OK (logs/m14-smoke.txt):
                                            2/0/2/0/0/0/0/3/1/3
real-CLI captures ........................ logs/m14-verify-A.txt (VERIFIED, 6 dimensions),
                                            logs/m14-verify-B.txt (VG-DATA-001),
                                            logs/m14-verify-F.txt (VG-OUT-001 + both hashes),
                                            logs/m14-demo-run.txt (exit 0, VERIFIED, 9 records)
manual G/H flows ......................... exit 1 each, VG-PROV-001,VG-PROV-005 / VG-PROV-002,
                                            provenance.log preserved after tamper+verify
node --check sweep ....................... 165 files: 163 clean, only the 2 intentional
                                            malformed fixtures fail (pre-existing)
comment audit ............................ M14-touched JS (inference.js, assurance.js,
                                            pipeline.test.js, inference.test.js,
                                            visionguard-sih.js): 0 comments
package.json ............................. untouched (mtime = extraction; dotenv only)
README counts ............................ both READMEs 819/166 → 822/166 + demo pointer
rule-ID inventory ........................ 36 IDs: DATA 001–012, MODEL 001–006, PROV 001–011,
                                            INFER 001–003, OUT 001–003, PIPE 001
```

### Self-review findings fixed before sign-off

1. **G/H doc one-liners were broken as first written** — `.replace(/\//g, path.sep)` inside the inline script still leaves backslash-escape damage in any single-quoted literal (`'C:\Users'` → `C:Users`) and fails on paths with spaces; replaced with the argv form and proved end-to-end on fresh demo copies before shipping the doc.
2. **Runner's scenario-I check was inverted** — it demanded `anchored === false` (supplied-but-mismatched); corrected to `=== true` to match the `null` = no-anchor-supplied semantics. Caught by the runner's own first 9/9 attempt reporting a false failure.
3. **`addFinding` silently dropped evidence fields** — `expected`/`actual`/`line` vanished from `report.findings` JSON (only `detail` text survived), which would have broken scenario F's structured assertions; fixed with the consumed-keys extras merge before any test was written against it.
4. **Temp-dir `provenance.log` disappearance investigated, not hand-waved** — several ad-hoc `%TEMP%` stores lost their log mid-session. Source audit: the only deletions in `src/visionguard/` are `.tmp` and lock cleanup (`store.js:78,:319,:337`); isolation re-tests (fresh demo → copy → one-liner → verify, G flow, H flow, verify-after-tamper, idle 25 s) all preserve the log at correct sizes; the losses tracked shell sessions dying mid-command, not any product path. Recorded as an environment artifact; the re-run evidence above all post-dates the investigation.

### Performance / debt

- Suite: +3 tests; full regression 40.8 s vs M13's 32.6 s (file-parallel variance; no new spawns in-suite — A's single bin spawn unchanged). Runner is standalone (~9 scenario copies × real CLI verify + one demo build), intentionally outside the suite.
- Debt carried: (a) hand-duplicated READMEs remain divergence-prone; (b) scenario D's tamper is append-only (unit covers in-place edits); (c) demo base copy-shared per suite process; (d) `DELIVERABLES.md` §7/§8 numbering is reconstructed until the prompt text is supplied — renumber-only fix if it differs.
- **No new dependencies, no comments in new or edited code.**

**Is this milestone genuinely complete and safe to build upon? — YES.**
Evidence: scenarios A–I pass `9/9` twice (suite + runner) with source-pinned rule IDs and required exit codes (A→0, B–H→1, I→3); scenario F proves expected-vs-actual SHA-256 in human *and* JSON output; full suite `822/801/3/18` with the identical pre-VisionGuard baseline trio; 10/10 bin smoke; `node --check` and comment audits clean; `package.json` untouched; both docs (`SIH_DEMO.md`, `DELIVERABLES.md`) shipped with captured, re-runnable evidence. This closes the M0–M14 program.

---

## Milestones 8–14

_Status: M0–M14 COMPLETE (checkpoints above) — final acceptance pass done._
