# VisionGuard — Deliverables & Acceptance Evidence (§7 / §8)

> **Source note.** The master prompt is not stored in this repository. This document maps every
> deliverable recorded for §8 (15 items) and every acceptance criterion recorded for §7
> (11 checkboxes) to its shipped artifact and evidence. The mapping is reconstructed from the
> approved M14 plan and the M0–M14 checkpoint record in `MILESTONE_CHECK.md`; every number,
> rule ID, command and log reference below is verbatim and re-runnable. If the prompt's own
> numbering differs, renumber against the prompt — the evidence does not change.

Evidence root: `CodeSentry/logs/` (M14 files) and `MILESTONE_CHECK.md` (per-milestone record).
All commands run from `CodeSentry/` on Node.js >= 18, Windows/macOS/Linux, no network.

---

## A. §8 — Deliverables (15)

### 1. Modified files — the five integration seams

| File | What changed (all additive; inert when VisionGuard is absent) |
|---|---|
| `src/findings/schema.js` | `provenance`/`assurance` finding categories accepted |
| `src/cli/commands.js` | `vision` command group dispatch |
| `src/cli/report.js` | six-dimension assurance block in scan reports |
| `src/cli/formatter.js` | `vision` table/JSON rendering |
| `bin/codesentry.js` | `vision` argv passthrough |

Plus: both `README.md` files (capability #9, CLI examples, 8 §13-style limitations, exit codes,
test counts, demo pointer) and `MILESTONE_CHECK.md` (checkpoints M0–M14, append-only).
Byte-identity of the core scanner with/without a verified store is proven by
`tests/unit/visionguard/integration.test.js` (M8 evidence, `MILESTONE_CHECK.md` §M8).

### 2. New source modules — 18 files, `src/visionguard/`

`assurance.js`, `canonical.js`, `cli.js`, `errors.js`, `findings.js`, `hash.js`, `index.js`,
`inference.js`, `keys.js`, `limits.js`, `manifest.js`, `metadata.js`, `model.js`, `paths.js`,
`pipeline.js`, `provenance.js`, `store.js`, `walk.js`.

### 3. New test files — 21 files

`tests/unit/visionguard/` (20): `assurance`, `canonical`, `cli`, `demo`, `errors`, `hash`,
`inference`, `integration`, `keys`, `limits`, `manifest`, `model`, `paths`, `performance`,
`pipeline`, `provenance`, `security`, `store`, `verdict`, `walk` (`.test.js`).
Plus `tests/integration/visionguard-pipeline.test.js` (9 end-to-end scenarios A–I).

### 4. New scripts — 2 files

| Script | Purpose | Evidence |
|---|---|---|
| `scripts/visionguard-demo.js` | builds the CV pipeline demo from scratch (dataset, model, keys, signing, anchoring, inference, deterministic re-execution) | `logs/m14-demo-run.txt` (exit 0, VERIFIED, 9 records) |
| `scripts/visionguard-sih.js` | one-command 9-scenario demonstration runner (A–I), exit 0/1/2/4, `--json`/`--out`/`--help` | `logs/m14-runner.json` (9/9 PASS) |

Neither writes inside the repository; artifacts go to the OS temp dir.

### 5. Documentation — 3 design/demo docs + 2 READMEs

`docs/visionguard/design.md` (architecture, schemas, threat model, CLI contract, test matrix,
limitations), `docs/visionguard/SIH_DEMO.md` (reproducible demonstration: one-command runner,
captured outputs, manual per-scenario command sequence from a clean checkout), and this file.
Both READMEs carry the capability list, example commands, the 8 honesty limitations, exit codes
and the current test counts (822/166).

### 6. Dependencies — none added

`package.json` dependencies: `dotenv` only (mtime unchanged from extraction: 10/02/2026
12:07:10). Signing uses `node:crypto` (Ed25519), hashing `node:crypto` SHA-256 — stdlib only.
`scripts/test-runner.js` and `package.json` scripts untouched.

### 7. Test-count delta — 324 → 822

| Suite run | tests | suites | pass | fail | skip |
|---|---:|---:|---:|---:|---:|
| Baseline (M0, before any change) | 324 | 85 | 321 | 3 | 0 |
| Final (M14, `logs/m14-full.txt`) | **822** | **166** | **801** | **3** | **18** |

Net: **+498 tests, +480 passes, same 3 pre-existing failures at identical locations**
(`tests/integration/pipeline.test.js:203`, `tests/unit/cli/auth.test.js:160`, `:174` — not
VisionGuard code, present at baseline). VisionGuard unit suite: 489/471/0/18.

### 8. Performance evidence — `logs/perf-gated.txt` (5/5 gated budgets met)

- Flood (100 000 small files): create=84 182 ms, register=102 332 ms, verify=117 836 ms,
  verify2=108 146 ms, heapGrowth=79 MiB (cap 768 MiB), manifest=14 MiB (cap 32 MiB)
- Huge (3 × 512 MiB): register=2 625 ms, verify=1 718 ms, heapGrowth=1 MiB
- Always-on hashing budget: 5 182 ms single-pass suite (runs ungated)
- Runtime envelope: full suite 40.8 s for 822 tests (`logs/m14-full.txt` duration_ms 40819)

### 9. Feature → requirement mapping

| Requirement | Rule IDs | Primary tests | Live evidence |
|---|---|---|---|
| Dataset integrity (hash binding, walk, limits) | `VG-DATA-001..012` | `security.test.js`, `assurance.test.js` (tamper-dataset/missing-dataset), `manifest.test.js` | scenario B, smoke step 9 (`logs/m14-verify-B.txt`, `logs/m14-smoke.txt`) |
| Model integrity (safetensors/onnx, schema) | `VG-MODEL-001..006` | `model.test.js`, `assurance.test.js` (tamper-model/missing-model) | scenario C (`logs/m14-runner.json`) |
| Pipeline identity | `VG-PIPE-001` | `pipeline.test.js` (unit + integration), `assurance.test.js` (tamper-pipeline) | scenario D |
| Inference record + input/model lineage | `VG-INFER-001..003` | `inference.test.js` | demo run (`logs/m14-demo-run.txt`) |
| Output hash with **expected vs actual** | `VG-OUT-001..003` | `inference.test.js` (expected/actual assertions), `visionguard-pipeline.test.js` F | scenario F — human output shows both hashes (`logs/m14-verify-F.txt`) |
| Provenance chain, signatures, anchors, rollback | `VG-PROV-001..011` | `provenance.test.js`, `security.test.js`, `visionguard-pipeline.test.js` E/G/H/I | scenarios E, G (`VG-PROV-001`), H (`VG-PROV-002`), I (UNANCHORED exit 3) |
| Anchored verdict truth table (`VERIFIED` unreachable when unsigned/unanchored) | dimension logic | `assurance.test.js`, `cli.test.js` (anchor flag matrix) | scenario A vs I (`logs/m14-verify-A.txt`) |
| CLI surface + exit-code map (0/1/2/3/4) | — | `cli.test.js`, `security.test.js` | 10-step smoke `10/10 OK` (`logs/m14-smoke.txt`) |
| Security hardening (traversal, hostile names, depth bombs, replay, TOCTOU, races) | security classes | `security.test.js` (19 e2e classes) | full run 0 new fails |
| Deterministic demo / re-execution honesty | — | `demo.test.js` | `logs/m14-demo-run.txt` ("re-execution: identical output bytes") |
| Performance budgets | — | `performance.test.js` (gated) | `logs/perf-gated.txt` |
| Zero new dependencies | — | — | `package.json` (this file, item 6) |

36 distinct rule IDs shipped: DATA 12, MODEL 6, PROV 11, INFER 3, OUT 3, PIPE 1.

### 10. CLI surface + exit-code map

Ten subcommands: `init`, `register-data`, `verify-data`, `register-model`, `verify-model`,
`record-pipeline`, `record-inference`, `verify-output`, `provenance`, `verify`.
Exit codes: `0` VERIFIED, `1` integrity violation, `2` usage, `3` incomplete
(unchecked/unsigned/unanchored), `4` internal. Proven end-to-end by the 10-command bin smoke
(`logs/m14-smoke.txt`: 2/0/2/0/0/0/0/3/1/3 — every expectation met).

### 11. Reproducible demonstration — single script + manual sequence

- One command: `node scripts/visionguard-sih.js` → 9/9 scenarios, exit 0
  (captured table in `SIH_DEMO.md` §2, machine form `logs/m14-runner.json`)
- Manual sequence from a clean checkout: `SIH_DEMO.md` §1–§4 (prerequisites, `npm install`,
  demo build, per-scenario copy → exactly one tamper → verify, with captured outputs for A–I)
- Same nine scenarios asserted as permanent tests:
  `node --test tests/integration/visionguard-pipeline.test.js` → 9/9 pass

### 12. Honesty scope — statements shipped with the feature

- `SIH_DEMO.md` §0: integrity = bit-identity only; accuracy **out of scope**
- Both READMEs: 8 numbered limitations (hash ≠ accuracy, untrusted clock, rollback needs an
  out-of-band anchor, byte-level output comparison, deterministic re-execution caveat, key
  compromise, tamper-evidence not -prevention, no blockchain/network log)
- Scenario I encodes the strongest honesty claim as a test: without an anchor the tool reports
  `INCOMPLETE`/`UNANCHORED` and **never** `VERIFIED`

### 13. Security hardening record (M10)

19 e2e attack classes green: path traversal, long/control/bidi filenames, manifest tamper,
anchored and unanchored rollback, oversized inputs, JSON depth bombs, signature stripping
(`VG-PROV-009`), key substitution (`VG-PROV-003`), record replay (`VG-PROV-006`), concurrent
register+verify, resource exhaustion, TOCTOU — plus three product hardenings recorded in
`MILESTONE_CHECK.md` §M10.

### 14. Checkpoint record

`MILESTONE_CHECK.md`: checkpoints M0–M13 already appended; M14 appended by this milestone.
Format per milestone: Status / What shipped / Design decisions / Evidence / Self-review
findings fixed / Performance / debt / completeness verdict. Append-only; audited each time.

### 15. Reproduction commands (clean checkout)

```powershell
git clone <repo> codesentry; cd codesentry/CodeSentry
npm install                                   # single dependency: dotenv
npm test                                       # 822 tests / 166 suites / 801 pass / 3 baseline fails
node scripts/visionguard-sih.js                # 9/9 scenarios, exit 0
node scripts/visionguard-demo.js --out vg-demo # clean demo build, VERIFIED
node --test tests/integration/visionguard-pipeline.test.js   # 9/9
```

---

## B. §7 — Acceptance checklist (11)

| # | Criterion (reconstructed from the prompt record) | Met | Evidence |
|---|---|---|---|
| 1 | Zero new dependencies; stdlib signing/hashing | ✅ | item 6 above; `package.json` mtime audit in `MILESTONE_CHECK.md` §M12 |
| 2 | No regressions: full suite green modulo the 3 pre-existing baseline failures | ✅ | `logs/m14-full.txt`: 822/166/801/3/18, failing trio identical to `logs/m13-full.txt` and M0 baseline |
| 3 | Six-dimension verification (dataset, model, pipeline, inference, output, provenance) fused into one verdict | ✅ | scenario A (`logs/m14-verify-A.txt`), `assurance.test.js` 20 tests |
| 4 | Provenance: signed chain, anchor semantics, rollback detected with anchor, `INCOMPLETE` never `VERIFIED` without one | ✅ | scenarios E/G/H/I; `provenance.test.js`, `security.test.js` |
| 5 | Output check shows **expected vs actual SHA-256** (scenario D requirement) | ✅ | `logs/m14-verify-F.txt` (human) + `findings[].expected/actual` (JSON); assertions in `inference.test.js`, pipeline test F |
| 6 | CLI exit-code contract 0/1/2/3/4 enforced by real binary invocations | ✅ | `logs/m14-smoke.txt` 10/10; `cli.test.js` |
| 7 | Security hardening: hostile inputs rejected without crash or escape | ✅ | 19 classes in `security.test.js`, 0 fails |
| 8 | Performance: 100 000 files ≤ budget, 512 MiB models, heap/manifest caps, always-on hashing budget | ✅ | `logs/perf-gated.txt` 5/5 + always-on 5 182 ms (item 8) |
| 9 | Reproducible demonstration: one script + documented manual sequence from clean checkout | ✅ | `scripts/visionguard-sih.js` 9/9 exit 0; `SIH_DEMO.md` §1–§4 with captured outputs |
| 10 | Honesty: hashes ≠ accuracy stated in user-facing docs; no overclaiming | ✅ | README limitations ×8, `SIH_DEMO.md` §0, scenario I test |
| 11 | Every milestone checkpointed with evidence, self-review and completeness verdict | ✅ | `MILESTONE_CHECK.md` M0–M14 |

---

## C. Known debt & non-claims

1. The 3 failing tests are pre-existing CodeSentry failures at baseline (M0) — out of
   VisionGuard scope, locations unchanged through M14.
2. Both READMEs are hand-duplicated and can drift (flagged since M12; counts refreshed M14).
3. Scenario D's tamper is append-only; an in-place pipeline code edit is covered at unit level.
4. The demo base runs once per suite process and is copy-shared (by design).
5. Environment note (M14): multi-step PowerShell sessions were observed dying mid-command,
   which stranded temp-dir artifacts; every product path (demo → copy → tamper → verify) was
   re-validated in isolation with the provenance log preserved (`G → VG-PROV-001,VG-PROV-005`,
   `H → VG-PROV-002`, clean store → VERIFIED). No product code deletes `provenance.log`
   (source audit: only `.tmp`/lock cleanup exists in `store.js`).

## D. Evidence index

| File | Proves |
|---|---|
| `logs/m14-full.txt` | final regression 822/166/801/3/18, scenarios A–I in-suite |
| `logs/m14-runner.json` | runner 9/9 PASS with per-scenario exit/verdict/rule |
| `logs/m14-smoke.txt` | 10/10 bin smoke, exit-code map |
| `logs/m14-verify-A.txt` | pristine store → VERIFIED, anchored, 6 dimensions |
| `logs/m14-verify-B.txt` | dataset tamper → `VG-DATA-001` in human output |
| `logs/m14-verify-F.txt` | output tamper → `VG-OUT-001` with expected vs actual hashes |
| `logs/m14-demo-run.txt` | demo from scratch → exit 0 VERIFIED, 9 records, re-execution byte-identical |
| `logs/perf-gated.txt` | gated performance budgets 5/5 |
| `logs/m13-full.txt`, `logs/m12-full.txt` | prior release bars (819, 813) |
| `MILESTONE_CHECK.md` | full M0–M14 decision/evidence trail |
