# VisionGuard — Architecture & Design Document

**Status:** Implemented through M14 — design + code + tests shipped; full record in `MILESTONE_CHECK.md` (M0–M14)
**Owner:** Principal Architect, VisionGuard subsystem
**Base:** CodeSentry v0.2.2 (Node.js >= 18, zero runtime deps beyond `dotenv`)
**Problem:** Trustworthy Computer Vision Integrity Assurance for Data, Models and
Inference Outputs in Multi-Contributor Pipelines (SIH).

---

## 0. Honesty statement (governs every section below)

| Concept | What VisionGuard says |
|---|---|
| Integrity verification | The artifact is **bit-identical** to what was registered (SHA-256 of bytes). |
| Provenance / attribution | **Who** registered/did what — only if records are **signed** *and* **anchored**. |
| Security analysis | ModelShield-style risk signals — a **separate** dimension, never merged into integrity. |
| Model correctness / accuracy | **Out of scope.** A hash never proves accuracy, fairness, absence of backdoors. |

VisionGuard is **tamper-evidence with attribution**, not tamper-prevention, and not a
correctness proof. Documentation, CLI output and demo narration must never claim otherwise.
An attacker who can write to the store and refuses to anchor can always produce a
self-consistent alternate history; only an out-of-band anchor defeats that.

---

## 1. Constraints inherited from CodeSentry (Milestone 0 evidence)

1. CommonJS, `node:*` stdlib only; sole declared dep is `dotenv` (used only by `bin/codesentry.js`).
   **VisionGuard must add no new dependency** (§8 shows stdlib covers signing).
2. CLI is a hand-rolled `CommandParser` in `src/cli/commands.js`; top-level commands are dispatched
   by `bin/codesentry.js`. Exit codes: `0` clean, `1` findings/gate, `2` usage/internal.
3. Findings require `createFinding()` with a `tool` from the `TOOLS` whitelist (`findings/schema.js:32`)
   and a `category` from `CATEGORIES`; normalizers register via `registerNormalizer()`.
4. `score()` is a 0–100 penalty metric; `verdict()` maps 80/50 → PASS/WARN/FAIL. **Integrity must not be
   diluted by this score** (§9.3).
5. `discovery/files.js` **cannot** be reused for dataset walking: it skips `.png/.jpg/.jpeg/.bmp/.zip/...`
   (exactly CV data), skips all dot-directories, and has no symlink/limit policy.
6. ModelShield is a pure regex **source** scanner and never deserializes model bytes — keep it untouched
   and surface it as a separate signal.
7. Tests: `node:test`, auto-globbed from `tests/**/**.test.js` by `scripts/test-runner.js`.
   No linter/formatter exists → static checks = `node --check` + full suite.
8. Baseline suite (recorded before any change): **324 tests / 85 suites / 321 pass / 3 fail**.
   The 3 failures are pre-existing and environmental; they must remain exactly 3.

---

## 2. Module layout

New package, placed per CodeSentry's `src/<subsystem>/` convention. Nothing existing is moved.

```
CodeSentry/src/visionguard/
├── index.js          # facade: createVisionGuard(options) — the only import the CLI needs
├── errors.js         # VgError + ERROR_CODES (typed, stable) + toFindingCode()
├── canonical.js      # canonicalJson(value), parseCanonical(str), hashRecord(obj)
├── hash.js           # hashFile(fd/path), hashBytes(), merkleRoot(entries), HEX/B64 helpers
├── paths.js          # normalizeRelPath(), assertInsideRoot(), collision detection
├── walk.js           # walkDataset(root, opts) -> {entries, findings, findingCounts, unreadable,
│                      #   collisions, stats, policy, realRoot}
├── limits.js         # DEFAULT_LIMITS + checkLimits() (typed errors)
├── manifest.js       # buildDatasetManifest(), verifyDataset(), diffDataset(), registerDataset(),
│                      #   validate/parse/checkConsistency
├── model.js          # registerModel(), verifyModel(), sniffFormat() (magic bytes, no load)
├── metadata.js       # metadataDepth()/assertMetadata() (shared untrusted-metadata caps)
├── pipeline.js       # computePipelineIdentity(), readRuntimeFacts(), registerPipeline(), verifyPipeline()
├── inference.js      # recordInference(), verifyInference()
├── keys.js           # ed25519 keygen/sign/verify via node:crypto (no new dep) + key registry I/O
├── store.js          # .visionguard/ I/O, atomic append with lock+fsync, load/save
├── provenance.js     # appendRecord(), verifyLog(), lineage(), anchors
├── assurance.js      # runAssurance() -> AssuranceReport (dimensions + overall verdict)
├── findings.js       # reportToFindings(report) -> CodeSentry findings (VG-* rule ids)
└── cli.js            # vision subcommand handlers, human table + JSON rendering

CodeSentry/tests/unit/visionguard/        # auto-discovered by the existing runner
├── canonical.test.js  hash.test.js  paths.test.js  limits.test.js
├── walk.test.js       store.test.js  errors.test.js
├── manifest.test.js   model.test.js pipeline.test.js inference.test.js
├── keys.test.js       provenance.test.js assurance.test.js  verdict.test.js
├── cli.test.js        security.test.js   # M10 adversarial regression suite
└── performance.test.js                   # M11 measurements (skipped-if-slow guarded)
CodeSentry/tests/integration/visionguard-pipeline.test.js   # M13–M14 scenarios A–I
```

**Files allowed to change (thin seams only):**

| File | Change | Why it cannot break existing behavior |
|---|---|---|
| `src/cli/commands.js` | `COMMANDS.VISION` + early branch capturing raw vision args | Branch only fires when `args[0] === 'vision'`; existing tests never pass it |
| `bin/codesentry.js` | dispatch branch (same pattern as `COMMANDS.DEMO`, line 141) | Independent `if` block, before the scan block |
| `src/cli/commands.js` `getHelp()` | one command line + examples | Help text is asserted only by substring (`commands.test.js:59`) |
| `src/findings/schema.js` | add `'visionguard'` to `TOOLS` | `schema.test.js:165` iterates `TOOLS` and passes for new entries; invalid-tool test uses another literal |
| `src/cli/report.js`, `src/cli/formatter.js` | section rendered **only if** `result.visionGuard` exists | Guarded → byte-identical output when VisionGuard is not used |

Everything else (`scan.js`, `scoring.js`, `verdict.js`, `modelshield.js`, `deployguard.js`,
`risk-graph.js`, `discovery/*`) is **not modified**.

---

## 3. Public interfaces

```js
const { createVisionGuard } = require('../visionguard');

const vg = createVisionGuard({
  root,                 // artifact root (project path) — required
  storeDir,             // default: <root>/.visionguard
  keyDir,               // default: ~/.codesentry/visionguard/keys  (PRIVATE keys live here)
  strict,               // default false; strict escalates policy findings to errors
  limits,               // overrides for DEFAULT_LIMITS
  anchor,               // { expectedHead } | { anchorFilePath } | null
  now,                  // injectable clock for deterministic tests
});

await vg.init({ contributor, operations });            // keypair + contributor registration
await vg.registerDataset({ path, name, version, policy });   // -> manifest
await vg.verifyDataset({ name, version, path });             // -> DatasetResult
await vg.registerModel({ path, id, version, format });       // -> model manifest
await vg.verifyModel({ id, version, path });
await vg.recordOperation({ op, inputs, outputs, parents, metadata, actor });
await vg.recordPipeline({ name, version, ... });             // -> pipeline identity
await vg.recordInference({ input, model, pipeline, output, params, actor });
await vg.verifyOutput({ recordId });
await vg.lineage({ artifact });                              // -> ancestors (DAG walk)
await vg.verifyAll();                                        // -> AssuranceReport
```

All methods return plain objects (no classes leak across the boundary) and throw `VgError`
only for *typed operational* failures; integrity mismatches are **returned as structured
results**, never thrown (so a full report can contain multiple failures).

---

## 4. Data schemas

`schema_version` is `"major.minor"`. Unknown **major** → reject (`VG_MANIFEST_VERSION`).
Unknown fields in hashed positions → reject in strict mode (`VG_MANIFEST_SCHEMA`).

### 4.1 Dataset manifest — `.visionguard/manifests/dataset/<name>/<version>.json`

```json
{
  "schema_version": "1.0",
  "kind": "dataset_manifest",
  "name": "demo-dataset", "version": "1.0.0",
  "created_at": "2026-10-02T12:00:00.000Z",
  "actor": { "contributor": "A", "key_id": "ab12…" },
  "hash_algorithm": "sha256",
  "file_count": 4, "total_bytes": 10240,
  "merkle_root": "sha256:9f2c…",
  "files": [ { "path": "images/0001.png", "size": 2048, "sha256": "a1b2…" } ],
  "policy": { "maxFileSize": 2147483648, "allowSymlinks": false, "extensions": ["*"] },
  "policy_findings": [ { "rule": "VG-DATA-005", "path": "link.png", "detail": "symlink excluded" } ],
  "record_hash": "sha256:…",
  "signature": "<base64 ed25519>"
}
```

* `files[]` is sorted by `path` (UTF-16 code-unit order).
* `record_hash = sha256(canonicalJson(manifest minus {record_id, record_hash, signature}))`.
* `signature = ed25519_sign(utf8(record_hash))` — the signature covers the **UTF-8 bytes of the
  full `sha256:<hex>` string**; verification checks the signature over the hash
  (unambiguous, no re-canonicalization ambiguity) and then the hash over the body.
* Duplicate-content files are allowed and distinct (identity is per-path); identical paths are impossible.

### 4.2 Provenance record — `.visionguard/provenance.log` (JSON Lines, one canonical record/line)

```json
{
  "schema_version": "1.0",
  "record_id": "sha256:…",
  "kind": "operation_recorded",
  "timestamp": "2026-10-02T12:00:01.000Z",
  "actor": { "contributor": "B", "key_id": "ab12…" },
  "operation": "preprocess",
  "inputs":  [ { "artifact": "dataset/demo-dataset@1.0.0", "sha256": "…" } ],
  "outputs": [ { "artifact": "dataset/demo-resized@1.0.0", "sha256": "…" } ],
  "parent_record_hashes": ["sha256:…"],
  "prev_record_hash": "sha256:…",
  "metadata": { "resize": "64x64", "normalize": "mean/std" },
  "record_hash": "sha256:…",
  "signature": "<base64>"
}
```

* **Kinds:** `contributor_registered`, `artifact_registered`, `operation_recorded`,
  `inference_recorded`.
* `record_id := record_hash` (content-derived; one hash avoids double-hashing ambiguity — documented choice).
  `record_id` is therefore **excluded from the hash input** (hashing it would be circular); the
  top-level `{record_id, record_hash, signature}` triple is removed by `hashRecord`.
* `record_hash = sha256(canonicalJson(record minus {record_id, record_hash, signature}))`;
  `signature = ed25519_sign(utf8(record_hash))` (UTF-8 bytes of the `sha256:<hex>` string).
* `prev_record_hash` = previous line's `record_hash` (linear chain); `parent_record_hashes[]`
  = DAG parents (must exist among records).
* `metadata` is **untrusted**: JSON depth ≤ 6, serialized size ≤ 4096 bytes, never executed,
  never interpolated into templates or commands.
* `timestamp` is UTC RFC 3339 with milliseconds. **A claim, not proof** (local clock untrusted).

### 4.3 Model manifest — `.visionguard/manifests/model/<id>/<version>.json`

```json
{
  "schema_version": "1.0", "kind": "model_manifest",
  "id": "demo-model", "version": "1.0.0", "format": "safetensors|onnx|pt|pth|other",
  "detected_format": "safetensors", "size": 4096, "sha256": "…",
  "created_at": "…", "actor": { "contributor": "C", "key_id": "…" },
  "metadata": { "framework": "declared-by-contributor" },
  "record_hash": "…", "signature": "…"
}
```

Format detection = **extension + magic-byte sanity check, zero deserialization** (§5.4).

### 4.4 Pipeline identity (§3.5 of the master prompt)

```json
{
  "schema_version": "1.0", "kind": "pipeline_identity",
  "preprocess_config": { "path": "preprocess.json", "sha256": "…" },
  "code": { "git_commit": null, "files": [ { "path": "pipeline.py", "sha256": "…" } ] },
  "dependency_lock": { "path": "requirements.lock", "sha256": "…" },
  "parameters": { "resize": "64x64" },
  "runtime": { "language": "node", "version": "v24.16.0",
               "libraries": [ { "name": "onnxruntime", "version": "…" } ] }
}
```
`pipeline_id = sha256(canonicalJson(this))`. Libraries are read from manifests/lockfiles **without
importing untrusted code**. This identifies the *declared and observed* pipeline — **not** a
guarantee of bit-for-bit reproducible execution.

Stored as `.visionguard/manifests/pipeline/<name>/<version>.json` with envelope fields
`{ schema_version, kind: "pipeline_manifest", name, version, created_at, actor, identity,
pipeline_id, record_hash, signature }`, where `pipeline_id = hashRecord(identity)` and
`record_hash = hashRecord(manifest)`. Both are recomputed **at load**, so a tampered file is
rejected with `VG_MANIFEST_HASH_MISMATCH` (stricter than the dataset/model manifests, which
defer the recomputation to their verify functions — the identity is self-contained here, so
recomputation needs no file access). File entries may carry a precomputed `sha256` (trusted
caller) or omit it and be hashed from `root` (lstat + `O_NOFOLLOW`, symlinks rejected).
`verifyPipeline` recomputes the identity from a supplied spec; any difference → `VG-PIPE-001`.

### 4.5 Inference record

```
INPUT hash + MODEL hash + PIPELINE identity  ==>  INFERENCE record  ==>  OUTPUT hash
```
Stored as a provenance record of kind `inference_recorded` with `inputs = [input, model, pipeline]`,
`outputs = [output]`, `metadata.params`, plus `metadata.output_mode = "raw" | "canonical_json"`
(default `raw`: raw output bytes; semantically equal but byte-different JSON **will** fail unless the
opt-in canonical mode was recorded).

Validation (deterministic, unit-tested): exactly three inputs — one loose input reference, one
`model/<id>@<version>` ref and one `pipeline/<name>@<version>` ref — and exactly one output.
`metadata.params` defaults to `{}`; `metadata.output_mode` must be `raw` or `canonical_json`.
Recording requires a key authorized for `infer` (`VG_UNAUTHORIZED_OP` otherwise).

`verifyInference({ recordId, root?, inputPath?, modelPath?, outputPath? })` maps checks to rules:
record not found / wrong kind / wrong shape, or resolved input bytes ≠ record → `VG-INFER-001`;
a parent that does not strictly precede the record → `VG-INFER-002`; model ref unregistered,
ref hash ≠ registration, superseded by a newer registered version ("stale"), or (when
`modelPath` is given) file bytes ≠ record → `VG-INFER-003`; pipeline ref unregistered or
ref hash ≠ registration → `VG-PIPE-001`; output missing/unreadable/not a regular file →
`VG-OUT-002`; output bytes ≠ record but equal to **another record's** recorded output →
`VG-OUT-003` (swapped); any other byte mismatch → `VG-OUT-001`. The inference status FAILs on
`VG-INFER-*`/`VG-PIPE-*` findings; `output_status` FAILs on `VG-OUT-*`; byte checks that cannot
be resolved to a file (no `root`/override, or a registered ref) are skipped → `NOT_CHECKED`.
Signatures, pinning and chain continuity remain the Provenance dimension's job; the §3 facade
method `verifyOutput({ recordId })` is the M8 name for this same function's output half.

### 4.6 Key registry — `.visionguard/keys/<contributor>/<key_id>.pub.json` (public only)

```json
{ "schema_version": "1.0", "kind": "public_key",
  "contributor": "B", "key_id": "ab12…", "algorithm": "ed25519",
  "public_key_der_b64": "…", "operations": ["curate_dataset","preprocess","train","export_model","infer"],
  "status": "active", "created_at": "…", "record_hash": "…", "signature": "…" }
```
`key_id = sha256(DER public key).hex[0:32]` (first 32 hex characters of the SHA-256 of the
SPKI DER public key — recomputable from the file contents, so a substituted DER cannot keep a
victim's `key_id`). The public-key record is **self-signed** (its own `signature` covers its own
`record_hash`). Private keys **never** enter the store: they live in
`keyDir` (default `~/.codesentry/visionguard/keys/`, `0600`) and are passed via `--key-file`.

### 4.7 Store metadata — `.visionguard/store.json`

```json
{ "schema_version": "1.0", "kind": "store", "created_at": "…",
  "hash_algorithm": "sha256", "record_hash": "…" }
```

---

## 5. Hashing, canonicalization and path policy

### 5.1 Canonical JSON (single function used everywhere: `canonical.js`)

RFC 8785-style rule set, documented on the function:

1. UTF-8 output; no insignificant whitespace.
2. Object keys sorted by **UTF-16 code unit** (JS default `Array.sort()` on strings) at every depth.
3. `NaN`/`Infinity` rejected (never silently `null`).
4. **Numbers:** integers only in hashed positions, `Number.isSafeInteger` required; non-integers and
   out-of-range values are rejected. (No float serialization in v1 — deliberate, documented
   deviation from full JCS: floats would be encoded as strings in `metadata`, which is untrusted
   anyway and never participates in identity beyond its canonical bytes.)
5. Strings must be well-formed Unicode; lone surrogates rejected.
6. Depth ≤ 32 on serialize; parse depth ≤ 32 and input ≤ 8 MiB by default; manifest documents are
   parsed under `maxManifestBytes` (32 MiB, amended in M11 — see §5.5).
7. `hashRecord(obj)` removes the **top-level** `{record_id, record_hash, signature}` fields
   (top-level only — a `record_id` nested inside e.g. `metadata` is still covered), canonicalizes,
   SHA-256s. **Never hash a string produced by a non-canonical serializer.**

### 5.2 File hashing (`hash.js`)

* SHA-256, streaming, **1 MiB** chunks, single pass, bounded memory (never reads whole file).
* Hash **from an open fd**: `open` → `fstat` (size, mtimeNs, ino) → read loop → `fstat` again →
  compare → re-`stat` the path and compare `ino/dev`. Any change ⇒ `VG_RACE_DETECTED`.
* Chunk-boundary sizes tested: 0, 1, chunk−1, chunk, chunk+1; known vectors for empty and `abc`.

### 5.3 Dataset identity — Merkle root with domain separation

```
leaf   = sha256( 0x00 || utf8(canonicalJson({path,size,sha256})) )
node   = sha256( 0x01 || left(32) || right(32) )
promo  = sha256( 0x02 || node(32) )          # odd node promoted, domain-separated
empty  = sha256( 0x03 || utf8("visionguard:dataset:empty:v1") )
```
Leaves are sorted by `path` first ⇒ root is independent of filesystem iteration order, OS and
locale. Prefix bytes prevent second-preimage confusion between leaf/node/promoted/empty.
Empty datasets are legal but always produce a **warning** (`VG-DATA-010`).

### 5.4 Path policy (`paths.js`)

* Normalize to **relative POSIX**: `\` → `/`; reject absolute paths, drive letters (`C:`),
  `..` segments, `.` segments, NUL and control characters (< 0x20), leading `/`.
* **Unicode NFC normalization** for identity; two distinct names colliding after NFC (or
  case-insensitively) within one dataset ⇒ registration error `VG_NFC_COLLISION` / `VG_CASE_COLLISION`.
* Component ≤ 255, full path ≤ 4096 ⇒ else `VG_PATH_TOO_LONG`.
* Containment: realpath the root once; `lstat` every entry (never `stat`) and **reject symlinks**;
  resolve the joined path and assert it stays inside the real root ⇒ else `VG_PATH_TRAVERSAL`.
* **Symlinks:** never followed; recorded as a policy finding and excluded (strict ⇒ fail).
* **Special files** (FIFO/socket/device): skipped + `VG-DATA-011` finding.
* **Archives** (`.zip/.tar/...`): hashed as opaque files. **No extraction, ever** (no zip-slip,
  no bomb surface). Documented; if extraction is ever added it must be off by default with its
  own limits.

### 5.5 Limits (`limits.js`)

`DEFAULT_LIMITS = { maxFiles: 100000, maxDirs: 100000, maxFileSize: 2 GiB, maxTotalBytes: 20 GiB,
maxDepth: 64, maxMetadataBytes: 4096, maxManifestBytes: 32 MiB, maxLogBytes: 512 MiB }`.
Exceeding any limit is a **typed error** (`VG_LIMIT_*`), never a hang or OOM. `maxDirs` bounds
walker breadth (stack frames per level) against directory-bomb traversal.
(`maxManifestBytes` was 8 MiB until M11; the 100 000-file target serializes to ~11 MiB of manifest
entries, so 8 MiB made the M11 target unregistrable. 32 MiB keeps a hard bound with headroom.)

---

## 6. Storage layout

```
<root>/.visionguard/
├── store.json                    # store metadata
├── manifests/
│   ├── dataset/<name>/<version>.json
│   ├── model/<id>/<version>.json
│   └── pipeline/<name>/<version>.json
├── provenance.log                # append-only JSONL (canonical records)
├── provenance.log.lock           # transient advisory lock (not committed)
├── keys/<contributor>/<key_id>.pub.json   # PUBLIC keys only
└── anchors/head.txt              # optional committed anchor (protected branch only)
```

* Private keys: `keyDir` (default `~/.codesentry/visionguard/keys/`), never inside the store.
* `.visionguard/` is dot-prefixed ⇒ CodeSentry's own walker (`SKIP_DIRS`/dot-dir skip) never
  crawls it during a normal `scan`.
* **Atomic append:** acquire `provenance.log.lock` (`open 'wx'`, retry ≤ 2 s, stale after 30 s) →
  `open(log, 'a')` → write full line → `fsync` → close → release. Temp+rename is *not* used for
  the log because rename-based replacement races concurrent appends on Windows; O_APPEND + lock +
  fsync is. `store.json`/manifests use write-temp → fsync → `rename` (atomic replace).
* **Log reads are whole-file, not windowed:** verification and chain-extension read the entire
  `provenance.log` (bounded by `maxLogBytes` → `VG_LIMIT_LOG`), so a truncated log cannot hide
  behind an unread tail window. The first record's `prev_record_hash` must be `null` (genesis);
  a first record claiming any other parent is `VG-PROV-001`. The log must be a regular file —
  symbolic links are rejected (`VG_SYMLINK_DENIED`) on both read and append so an append can
  never be redirected through a link. Verify snapshots the log under the same advisory lock
  used by writers.

---

## 7. Verification flow (`runAssurance`)

```
1  load store.json (+schema major check)
2  DATASET     re-walk with stored policy → re-hash EVERY file (no cache by default)
              → diff vs manifest (path-keyed maps, O(n)) → unchanged/modified/added/removed/
                renamed/unreadable/policy-violating
3  MODEL       re-hash registered model files + magic re-check + registration check
4  PIPELINE    recompute pipeline identity from current declared inputs
5  INFERENCE   re-hash input & output files; compare with record; validate record placement
6  PROVENANCE  chain continuity, parents exist, artifact hashes match registrations,
              signer registered+active+authorized+**pinned by its contributor registration**,
              no cycles, no duplicate record_hash,
              timestamp monotonicity vs parents (warn), conflicting (name,version) hashes flagged
7  ANCHOR      compare head record_hash with --expected-head / --anchor-file / CI variable
8  DIMENSIONS  map per §8 → overall verdict §8.2
9  OUTPUT      human table (default) or JSON; findings adapter §9.1; exit code §11.4
```

Default = **full rehash** (verification used for security decisions must not trust a
same-size/same-mtime cache). A future opt-in cache may be keyed on
`(path, size, mtime_ns, inode)` and must default off; `--no-cache` always forces full rehash.

**Record integrity vs execution truth:** steps 2–7 prove *record integrity* (bytes and chain were
not altered). They do **not** prove the inference was really executed with that model on that
input. The demo pipeline additionally **re-executes** deterministic inference and compares
outputs — that is a demo-only check of execution truth, documented as such.

---

## 8. Verdict model

### 8.1 Per-dimension results

```
Dataset Integrity     PASS | FAIL | NOT_CHECKED | UNANCHORED
Model Integrity       PASS | FAIL | NOT_CHECKED
Pipeline Integrity    PASS | FAIL | NOT_CHECKED
Inference Integrity   PASS | FAIL | NOT_CHECKED
Output Integrity      PASS | FAIL | NOT_CHECKED
Provenance            PASS | FAIL | NOT_CHECKED | UNSIGNED | UNANCHORED
```

Exact mapping rules (deterministic, unit-tested):

| Dimension | FAIL | PASS | UNANCHORED / UNSIGNED | NOT_CHECKED |
|---|---|---|---|---|
| Dataset | any diff, or manifest `record_hash` mismatch, or manifest hash conflicts with its signed provenance record | files match **and** manifest bound by a valid signed record | files match manifest but **no signed binding/anchor** → `UNANCHORED` | no dataset registered/requested |
| Model | bytes differ, missing, or magic mismatch vs registered | bytes match + registered + magic sane | — | not registered/requested |
| Pipeline | recomputed identity ≠ recorded | recomputed = recorded | — | not registered/requested |
| Inference | record invalid / parent missing / stale model ref | record valid + chain placement valid | — | not recorded/requested |
| Output | output bytes ≠ record (or missing/malformed/swapped) | bytes match record | — | not recorded/requested |
| Provenance | chain/signature/parent/anchor violations, replay, cycle, forgery | chain valid **and** signatures valid **and** anchored | one or more records unsigned → `UNSIGNED`; chain + signatures valid but no expected head supplied/matching → `UNANCHORED` | no log |

### 8.2 Overall verdict

```
any FAIL                  -> INTEGRITY VIOLATION
no FAIL, any of {NOT_CHECKED, UNANCHORED, UNSIGNED} -> INTEGRITY VIOLATION?  NO -> INCOMPLETE
all PASS                   -> VERIFIED
```
`VERIFIED` is therefore **unreachable** unless every dimension was checked, all signatures
verified, and an out-of-band anchor matched. This is enforced by a single pure function with
truth-table tests — not by scattered conditionals.

### 8.3 Dependency decision: signing

**No new dependency.** Node's `node:crypto` provides Ed25519 natively
(`generateKeyPairSync('ed25519')`, `sign(null, msg, key)`, `verify(null, msg, key, sig)`) since
Node 12, satisfying `engines >= 18` and the CI matrix (18/20/22 × win/linux).
Tradeoff vs. a `cryptography`-style third-party library: none of its extra features (X.509, cert
chains, AES-GCM helpers) are needed; adding it would violate the zero-dependency posture and add
supply-chain surface for zero benefit. Recorded as **new dependencies: none**.

---

## 9. Integration plan

### 9.1 Findings (rule ID namespace)

`findings.js` converts an `AssuranceReport` into CodeSentry findings:
`tool: 'visionguard'`, `category: 'security'`, `file` = the affected artifact path (or
`.visionguard/provenance.log` for log-level issues), `confidence: 'high'`.

| Rule | Condition | Severity |
|---|---|---|
| `VG-DATA-001..004` | modified / missing / added / renamed | BLOCKER |
| `VG-DATA-005` | symlink excluded (strict: failed) | HIGH |
| `VG-DATA-006` | NFC or case collision | BLOCKER |
| `VG-DATA-007` | manifest tampered (`record_hash` mismatch) | BLOCKER |
| `VG-DATA-008` | unreadable file | HIGH |
| `VG-DATA-009` | limit exceeded | HIGH |
| `VG-DATA-010` | empty dataset | INFO |
| `VG-DATA-011` | special file skipped | INFO |
| `VG-DATA-012` | file excluded by extension policy | INFO |
| `VG-MODEL-001..004` | modified/missing / magic mismatch / empty / unregistered | BLOCKER |
| `VG-MODEL-005` | pickle-based format detected (**security signal, not integrity**) | HIGH |
| `VG-MODEL-006` | model manifest tampered (`record_hash` mismatch) | BLOCKER |
| `VG-PIPE-001` | pipeline identity invalid or unregistered, ref hash ≠ registration, or recomputed identity differs | BLOCKER |
| `VG-INFER-001` | inference record missing / wrong kind / wrong shape, or input bytes ≠ record | BLOCKER |
| `VG-INFER-002` | parent does not strictly precede the inference record | BLOCKER |
| `VG-INFER-003` | model ref unregistered / hash ≠ registration / superseded version / model file ≠ record | BLOCKER |
| `VG-OUT-001` | output bytes ≠ record | BLOCKER |
| `VG-OUT-002` | output missing, unreadable or not a regular file | BLOCKER |
| `VG-OUT-003` | output bytes match a different record's output (swapped) | BLOCKER |
| `VG-PROV-001` | chain broken: malformed line, `record_hash` mismatch, or `prev_record_hash` ≠ previous line | BLOCKER |
| `VG-PROV-002` | bad signature (signature does not verify over `record_hash`) | BLOCKER |
| `VG-PROV-003` | unknown signer (no key record, or key file missing/tampered) | BLOCKER |
| `VG-PROV-004` | unauthorized signer (key `status: revoked`, or `operation` ∉ key `operations`) | BLOCKER |
| `VG-PROV-005` | missing parent (`parent_record_hashes` entry not present earlier in the log) | BLOCKER |
| `VG-PROV-006` | replay (duplicate `record_hash` already seen) | BLOCKER |
| `VG-PROV-007` | cycle (parent index ≥ current record, or self-parent) | BLOCKER |
| `VG-PROV-008` | anchor mismatch (head `record_hash` ≠ `--expected-head` / anchor file) | BLOCKER |
| `VG-PROV-009` | UNSIGNED (one or more records carry no signature) | HIGH |
| `VG-PROV-010` | conflicting `(name,version)` hashes across `artifact_registered` records | BLOCKER |
| `VG-PROV-011` | artifact ref hash ≠ registered manifest hash (dataset `merkle_root` / model `sha256`) | BLOCKER |

`VG-PROV-003` covers **key pinning**: each `contributor_registered` record pins the set of
`key_id`s that contributor may sign with (rotation = append another registration). A record
signed by a key not pinned by the latest registration covering its timestamp is an unknown
signer — a spare, unregistered key must not be able to forge records for a known contributor.

Warning rules are reported with severity `WARN` (they never flip a dimension to `FAIL`):

| Rule | Condition |
|---|---|
| `VG-PROV-W001` | record timestamp earlier than a parent's timestamp (non-monotonic) |
| `VG-PROV-W002` | unverifiable artifact ref (manifest not registered, or unparsable ref ignored) |
| `VG-PROV-W003` | key registry `operations` differ from the contributor registration's view |
| `VG-PROV-W004` | valid signature from a key with no `contributor_registered` record |

### 9.2 Verdict / score (anti-dilution)

* `vision verify` computes its own overall verdict (§8.2) — it never consults `core/scoring.js`.
* When VisionGuard is enabled in a scan, `result.visionGuard` is attached and, **only in that case**,
  the scan-level verdict is forced to `FAIL` if overall = INTEGRITY VIOLATION, and the exit code is
  forced to ≥ 1 regardless of `score.value`. A 100/100 codebase with a tampered dataset must never
  exit 0.
* With VisionGuard disabled (default), `scan()` output is **byte-identical** to baseline — verified
  in M8 by diffing captured JSON before/after.

### 9.3 Reports

* JSON: `--json` prints the `AssuranceReport` verbatim (stable field names, `schema_version`).
* Terminal: the §8.1 assurance table rendered with the existing `theme`/`OutputHandler` helpers.
* Markdown: a guarded `visionGuardSection` in `report.js` (only when `result.visionGuard` exists).

### 9.4 Risk graph

When a VisionGuard result is present, add nodes `{type:'ARTIFACT'}` and `{type:'CONTRIBUTOR'}`
with edges `DERIVED_FROM` / `TRUSTS` (contributor signed artifact) to the existing
`SoftwareRiskGraph` — additive, only when VG data is supplied, so `build()` output for normal
scans is unchanged.

### 9.5 ModelShield

Untouched. `vision register-model` reports `format` and, for pickle-based formats (`pt/pth`
without a ZIP container), surfaces `VG-MODEL-005` alongside — but ModelShield findings and
VisionGuard integrity results are always rendered in **separate sections** with separate verdicts.

### 9.6 CI

* New optional step: `node CodeSentry/bin/codesentry.js vision verify --json --expected-head "$VG_HEAD"`.
* Exit codes (§11.4) gate the pipeline: `INTEGRITY VIOLATION` always fails;
  `INCOMPLETE` fails only with `--require-verified` (configurable, documented).
* Anchor supplied via CI variable (preferred) or a committed `anchors/head.txt` on a protected branch.

---

## 10. Threat model

Assets: dataset bytes, model bytes, pipeline config/code, inference inputs/outputs,
provenance history, contributor identities, the anchor.

| # | Attacker capability | Defended? | Mechanism | Residual risk |
|---|---|---|---|---|
| T1 | Edit a dataset file | **Yes** | re-hash vs manifest → `FAIL`, exact file identified | none for detection |
| T2 | Add/remove/rename files | **Yes** | O(n) diff, rename detected via same-hash/different-path | — |
| T3 | Swap the model | **Yes** | model manifest hash + magic re-check → `FAIL` | — |
| T4 | Edit output JSON | **Yes** | output re-hash vs record → `FAIL` w/ expected vs actual | byte-level only (§13) |
| T5 | Rewrite manifest *and* data together | **Partially** | signed manifest binding + log ⇒ detectable **iff anchored**; without anchor ⇒ `UNANCHORED`, never `VERIFIED` | attacker with write access and no anchor can forge a consistent store — **stated openly** |
| T6 | Rewrite/reorder/truncate/replay the log | **Partially** | hash chain + duplicate detection + parents ⇒ detects in-place edits and partial rewrites; **full rollback detected only with an anchor** | unanchored rollback ⇒ reported `UNANCHORED`, never `VERIFIED` |
| T7 | Forge a contributor / signature | **Yes** | Ed25519 over `record_hash`; unregistered/revoked/unauthorized signer ⇒ `FAIL` | stolen private key ⇒ attribution forgery (key compromise is out of scope, stated) |
| T8 | Register their own key as a new contributor | **Partially** | key registration is itself a signed log record; if they can append, they become a *legitimate but new* contributor whose actions are attributed and anchor-visible | malicious-yet-valid contributor can sign bad data — out of scope (§13) |
| T9 | Race the verifier (swap file during hashing) | **Yes** | hash from fd + `fstat` before/after + re-stat ⇒ `VG_RACE_DETECTED` | extremely narrow kernel-level races beyond scope |
| T10 | Path traversal / malicious filenames | **Yes** | §5.4 policy + realpath containment + length/control-char/NFC checks | — |
| T11 | Symlink/hardlink escape | **Yes** | `lstat`-first, symlinks never followed, special files skipped | hardlink to a file inside root is still inside root (identity preserved) |
| T12 | Resource exhaustion (huge file/dir/JSON/log) | **Yes** | §5.5 limits, streaming hashing, parse caps | limits are configurable; a user raising them accepts the cost |
| T13 | Strip signatures to dodge verification | **Yes** | missing signature ⇒ `UNSIGNED` ⇒ `INCOMPLETE`, never `VERIFIED` | — |
| T14 | Corrupt log via concurrent writers | **Yes** | lock + O_APPEND + fsync; parallel-writer tests | lock is advisory; two machines writing the same NFS log unsupported (documented) |
| T15 | Confuse leaf vs node hashes (second preimage) | **Yes** | domain-separation prefixes §5.3 | — |
| T16 | Make integrity look like a security/accuracy claim | **Yes** | §0 honesty table enforced in wording of all outputs | — |

**Explicitly NOT defended:** model accuracy/backdoors; semantic (non-byte) output equality unless
opt-in canonical mode; local clock honesty; a compromised anchor; key theft; a malicious
contributor signing validly-formed bad data; tampering that happens *after* verification
(freshness is the caller's job).

---

## 11. Error model, CLI and exit codes

### 11.1 Typed errors

```js
class VgError extends Error { constructor(code, message, details = {}) }  // code: stable string
```
Codes (stable, machine-matchable): `VG_PATH_TRAVERSAL`, `VG_PATH_ABSOLUTE`, `VG_PATH_NUL`,
`VG_PATH_INVALID`, `VG_PATH_TOO_LONG`, `VG_NFC_COLLISION`, `VG_CASE_COLLISION`,
`VG_SYMLINK_DENIED`, `VG_RACE_DETECTED`, `VG_UNREADABLE`, `VG_LIMIT_FILE_COUNT`,
`VG_LIMIT_DIR_COUNT`, `VG_LIMIT_FILE_SIZE`, `VG_LIMIT_TOTAL_BYTES`, `VG_LIMIT_DEPTH`,
`VG_LIMIT_METADATA`, `VG_LIMIT_MANIFEST`, `VG_LIMIT_LOG`, `VG_MANIFEST_MALFORMED`, `VG_MANIFEST_SCHEMA`,
`VG_MANIFEST_VERSION`, `VG_MANIFEST_HASH_MISMATCH`, `VG_CANONICAL_INVALID`,
`VG_NOT_REGISTERED`, `VG_KEY_UNKNOWN`,
`VG_KEY_REVOKED`, `VG_UNAUTHORIZED_OP`, `VG_ANCHOR_MISMATCH`, `VG_STORE_LOCKED`,
`VG_INTERNAL`.

Operational problems **throw** `VgError`; integrity mismatches are **returned** as structured
results so one run can report many. Error messages use root-relative paths (never absolute
system paths) to avoid leaking the operator's filesystem layout.

### 11.2 Command set (adapted to CodeSentry conventions)

```
codesentry vision init                # create .visionguard/, generate keypair, register contributor
codesentry vision register-data  <dir> [--name] [--version] [--actor]
codesentry vision verify-data     [<dir>] [--strict]
codesentry vision register-model  <file> [--id] [--version] [--format]
codesentry vision verify-model    <file|id>
codesentry vision record-pipeline [--name] ...
codesentry vision record-inference <input> <output> --model <id> --pipeline <name> --actor
codesentry vision verify-output   <output>
codesentry vision provenance      [--artifact X] [--graph] [--verify]
codesentry vision verify          [--expected-head H | --anchor-file F] [--strict]
                                  [--json] [--require-verified]
```
Global-to-group flags: `--json`, `--store <dir>`, `--key-file <f>`, `--verbose`.
**No interactive prompt when non-TTY or `--json`** (mirrors `ensureAuth`'s CI check); `vision init`
in CI mode requires `--actor`/`--key-file` instead of prompting.

### 11.3 Output

* Human: the §8.1 assurance table + per-dimension detail lines + actionable next step.
* JSON: single object `{ schema_version, command, overall, dimensions, details, findings, anchored }`.

### 11.4 Exit codes (stable)

| Code | Meaning |
|---|---|
| 0 | `VERIFIED` (or command succeeded: init/register/record) |
| 1 | `INTEGRITY VIOLATION` (consistent with CodeSentry's "findings ⇒ 1") |
| 2 | usage / invalid arguments (consistent with existing parser behavior) |
| 3 | `INCOMPLETE` (unchecked / unsigned / unanchored) |
| 4 | internal error (unexpected exception inside VisionGuard) |

`scan`/`deployguard` exit behavior is unchanged.

### 11.5 Parser integration

`CommandParser.parse` gains an **early branch**: if `args[0] === 'vision'`, capture
`result.visionArgs = args.slice(1)` verbatim and return — no option parsing, no
`Unknown argument` errors, no `projectPath` mangling. `bin/codesentry.js` dispatches to
`src/visionguard/cli.js`. Existing commands and their tests are untouched.

---

## 12. Test plan (maps to milestones)

| Milestone | Tests (in `tests/unit/visionguard/` unless noted) |
|---|---|
| M2 hashing | known vectors (empty, `abc`), determinism across runs, chunk sizes 0/1/1MiB±1, canonical stability (key order, unicode, numbers), bounded memory on a large sparse file |
| M3 dataset | valid, modified, deleted, added, renamed, corrupted, empty, duplicate content, nested, unsupported ext, symlink in/out, permission error, large file, case/NFC collision, tampered manifest (root vs file list), malformed JSON, wrong schema version |
| M4 model | valid, modified, replaced, unsupported, malformed/truncated, metadata mismatch, zero-byte, extension/magic mismatch, **canary proving pickle payload never executes** |
| M5 provenance | key registry (keygen, self-signed record, key-id recomputation, key substitution), store.json roundtrip + tamper, lock (stale/fresh/contended), log size limit, multi-contributor chain, missing parent, wrong parent hash, altered config, wrong model ref, broken chain (edit/delete/reorder/truncate/duplicate), forged signature, unregistered/revoked signer, unauthorized op, conflicting versions, cycle, concurrent appends, crash-mid-write, replay |
| M6 inference | valid; modified input/model/output; missing/malformed output; inconsistent metadata; output swapped between records; unregistered model reference; stale model version |
| M7 demo | deterministic re-execution equality; four contributors A–D |
| M10 security | path traversal, long/control/RTL filenames, symlink+hardlink, TOCTOU, manifest tamper, unanchored rollback reported as UNANCHORED, oversized inputs, JSON depth bombs, signature stripping, key substitution, replay, concurrent verify+register, resource exhaustion |
| M11 perf | 100k small files, few huge files, repeated verification, memory ceiling, no double hashing |
| M13 | scenarios A–F as automated tests (each resets state, applies exactly one tamper, asserts expected verdict) |
| M14 | scenarios G–I (edited middle record → `VG-PROV-001`, forged signature → `VG-PROV-002`, rollback without anchor → UNANCHORED exit 3) + expected-vs-actual hashes in `VG-OUT-001` + one-command runner `scripts/visionguard-sih.js` driving all nine scenarios through the real bin |

Property/randomized tests are used for canonicalization and Merkle determinism **only if** they
run offline and deterministically (seeded PRNG from `node:crypto`/fixed seeds — no new dependency).
All tests use `fs.mkdtempSync(os.tmpdir())` + `t.after` cleanup, matching existing conventions.

---

## 13. Known limitations (must appear in user-facing docs)

1. A hash proves bit-identity only — never accuracy, safety, fairness or absence of backdoors.
2. Local clock is untrusted; timestamps are claims.
3. Rollback of the whole store is **undetectable without an out-of-band anchor**.
4. Output comparison is byte-level; semantically equal JSON fails unless opt-in canonical mode was
   recorded at inference time.
5. Execution truth of an inference is only checkable via deterministic re-execution (demo does this;
   the general product cannot).
6. Key compromise breaks attribution; a malicious contributor can sign valid-but-bad data.
7. Tamper-*evidence*, not tamper-*prevention*: an attacker with write access can still destroy data.
8. No blockchain, no network service, no external transparency log (deliberate).

---

## 14. Design review — top 10 ways this design could fail

| # | Failure mode | Mitigation |
|---|---|---|
| 1 | Manifest + data rewritten together, verifier says `VERIFIED` | Impossible by construction: `VERIFIED` requires signatures **and** an anchor (§8.2 truth table) |
| 2 | Canonicalization malleability (two serializations, one hash) | One canonical function, hash excludes top-level `{record_id, record_hash, signature}`, strict key set, rejected floats/NaN/depth bombs (§5.1) |
| 3 | Log rebuilt from scratch with internally valid hashes | Chain + parents detected only for *partial* rewrites; full rebuild defeated by `--expected-head` anchor; unanchored ⇒ `UNANCHORED`, never `VERIFIED` |
| 4 | Integrity failures diluted by a 100/100 score | VG verdict is independent; FAIL forces exit ≥ 1 and scan verdict `FAIL` (§9.2) |
| 5 | Reusing `discovery/files.js` silently drops all images | Explicit non-reuse documented (§1.5); dedicated walker with its own tests asserting `.png` is included |
| 6 | TOCTOU: file swapped between hash and verdict | Hash from fd with before/after `fstat` + re-stat (§5.2) |
| 7 | Windows-specific breakage (locks, case-insensitive FS, CRLF) | O_APPEND+lock (rename races avoided), case-collision detection at registration, hashing raw bytes (no newline translation on `fs` binary reads), CI matrix already includes `windows-latest` |
| 8 | Signatures silently dropped ⇒ false PASS | `UNSIGNED` is a first-class dimension; §8.2 forbids `VERIFIED` when present |
| 9 | Concurrent appends corrupt the log | Advisory lock + fsync + parallel-writer and crash-mid-write regression tests |
| 10 | Demo drifts from reality (mocked/hardcoded results) | M13–M14 scenarios (A–I) are automated tests that reset state, apply exactly one tamper, and assert the expected verdict; demo artifacts are generated, never committed pre-baked |

Runners-up and their handling: huge JSON/log (size+depth caps, §5.5) · symlink/hardlink escape
(`lstat`-first policy, §5.4) · key substitution (registration is itself a signed, anchored record,
T8) · rename false-positives (same-hash/different-path pair logic in the diff, tested) ·
`record_id`/`record_hash` ambiguity (defined equal, documented §4.2).
