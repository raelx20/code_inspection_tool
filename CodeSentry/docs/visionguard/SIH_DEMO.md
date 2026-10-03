# SIH Demonstration — Trustworthy Computer Vision Integrity Assurance

This is the reproducible demonstration procedure for:

> "Trustworthy Computer Vision Integrity Assurance for Data, Models and Inference Outputs in Multi-Contributor Pipelines."

Everything below runs from a clean checkout on Node.js >= 18. There is no GPU requirement, no ML
framework, no network access, and no pre-baked result committed to the repository — every run
regenerates the artifacts from scratch.

---

## 0. Honesty scope (what the demo does and does not prove)

| Concept | What VisionGuard says |
|---|---|
| Integrity verification | Artifact is bit-identical to what was registered |
| Provenance / attribution | Who registered/did what, if signed and anchored |
| Security analysis | ModelShield-style risk signals (separate from integrity) |
| Model correctness / accuracy | **Out of scope; not established by hashes** |

---

## 1. Prerequisites

```powershell
git clone <repo> codesentry
cd codesentry/CodeSentry
npm install          # single dependency: dotenv
node --version       # must be >= 18 (see package.json "engines")
```

All commands below assume your shell's working directory is the `CodeSentry/` directory.
Set a `repo` variable once so later commands can locate the CLI regardless of where you `cd`:

```powershell
# PowerShell (run from CodeSentry/)
$repo = (Resolve-Path .).Path
```

```bash
# bash (run from CodeSentry/)
repo="$(pwd)"
```

---

## 2. One-command reproducible run (automated, all 9 scenarios)

```text
node scripts/visionguard-sih.js
```

The runner builds one pristine demo pipeline, copies it per scenario, applies **exactly one
tamper** per copy (scenario A applies none), verifies every copy through the **real
`codesentry vision` CLI**, and asserts exit code, overall verdict and rule IDs.
Captured output from a real run (exit code 0):

```text
SIH demonstration run (9 scenarios, workdir: C:\Users\91797\AppData\Local\Temp\vg-sih-71496)

Scenario  Exit  Overall              Evidence                                      Result
A         0     VERIFIED             anchored, 6 dimensions PASS                   PASS
B         1     INTEGRITY VIOLATION  VG-DATA-001                                   PASS
C         1     INTEGRITY VIOLATION  VG-MODEL-001                                  PASS
D         1     INTEGRITY VIOLATION  VG-PIPE-001                                   PASS
E         1     INTEGRITY VIOLATION  VG-PROV-008                                   PASS
F         1     INTEGRITY VIOLATION  expected c957f57dff9c... got a4994a93493f...  PASS
G         1     INTEGRITY VIOLATION  VG-PROV-001                                   PASS
H         1     INTEGRITY VIOLATION  VG-PROV-002                                   PASS
I         3     INCOMPLETE           provenance UNANCHORED, never VERIFIED         PASS

9/9 scenarios matched the expected verdicts
```

Runner flags: `--json` (machine-readable summary), `--out <dir>` (keep artifacts in a chosen
directory), `--help`. Exit codes: `0` all scenarios matched, `1` mismatch, `2` usage, `4` internal.

The same nine scenarios are asserted by the automated test suite:

```powershell
node --test tests/integration/visionguard-pipeline.test.js   # 9/9 pass
```

---

## 3. Build the clean pipeline from scratch (scenario A's starting point)

```text
node scripts/visionguard-demo.js --out vg-demo
```

Real captured output (exit code 0):

```text
VisionGuard CV pipeline demo
  workspace : C:\Users\91797\AppData\Local\Temp\vg-sih-capture\demo-run
  honesty   : hashes prove bit-identity only, never accuracy or safety
  records   :
    contributor A  key 87298ef53e0ad706511b3b531da08b0b  ops curate_dataset
    contributor B  key 95935304d7bbbf62f5de3ba9d4218bef  ops preprocess
    contributor C  key 311844ef2b00d6272400e69f7c8aa217  ops train,export_model
    contributor D  key f1c82da5e8ddb049f9aaa8126d45e3f1  ops infer
  dimensions:
    Dataset     PASS  (32 files, sha256:56b76dace21bf25bf8ab1e096ec8a984dc97d2eb67bd4f134cb5c6c6969517ea)
    Model       PASS  (safetensors, sha256:1c834b49444f062b575ad7677a65d5a715c37ccf5079705c0be91c048f962fd2)
    Pipeline    PASS  (sha256:12f90274972bde3f0b6bb70a7998eef3985be35764e77e4df13c19bd50cefc0a)
    Inference   PASS  (record sha256:d49d80e30300460b0daf602dc78275c1fd1cb15f8adbb8b0e61f259a6ce3b9b7)
    Output      PASS  (expected sha256:c957f57dff9c4b8a716dab8e162b1b209d89932abef5125c7c2a581bbc616273)
    Provenance  PASS  (9 records, head sha256:d49d80e30300460b0daf602dc78275c1fd1cb15f8adbb8b0e61f259a6ce3b9b7)
  re-execution: identical output bytes
  overall: VERIFIED
```

What it creates (identical for every scenario copy):

```text
vg-demo/
  dataset/{circle,cross,square,triangle}/00-07.png   32 generated images (deterministic, no external data)
  model/demo-clf.safetensors                          tiny deterministic classifier (magic-byte safe format)
  pipeline.js, preprocess.json                        pipeline code + fixed preprocessing config
  inputs/input.png                                    inference input
  outputs/prediction.json                             inference output
  keys/{A,B,C,D}/...key                               demo private keys (A dataset, B preprocessing, C model, D inference)
  .visionguard/                                       store: manifests/, provenance.log, keys/*.pub.json, anchors/head.txt
```

Nothing here is pre-computed: the dataset is generated, registered, signed, anchored and verified
on every run, and inference is re-executed to prove byte-identical output.

---

## 4. Manual command sequence (each scenario: reset, one tamper, verify)

Every scenario starts from an identical clean copy, applies **exactly one** tamper, and runs one
verification. Run the setup once per scenario:

```powershell
# PowerShell — setup (repeat for each scenario letter)
Copy-Item -Recurse vg-demo vg-demo-B
Set-Location vg-demo-B
```

```bash
# bash — setup (repeat for each scenario letter)
cp -r vg-demo vg-demo-B
cd vg-demo-B
```

Tamper commands are `node -e` one-liners so they behave identically in PowerShell and bash.
Verify with:

```text
node "$repo/bin/codesentry.js" vision verify        # PowerShell ($repo set in step 1)
node "$repo/bin/codesentry.js" vision verify        # bash (repo set in step 1)
echo "exit=$LASTEXITCODE"                            # PowerShell        (bash: echo "exit=$?")
```

### Scenario A — everything valid → VERIFIED

No tamper. Real captured output (exit code 0):

```text
VisionGuard Assurance

  Dataset Integrity     PASS
  Model Integrity       PASS
  Pipeline Integrity    PASS
  Inference Integrity   PASS
  Output Integrity      PASS
  Provenance            PASS

  Overall: VERIFIED
  Anchored: yes

Details:

  dataset demo-dataset@1.0.0: PASS
  model demo-clf@1.0.0: PASS
  pipeline demo-cv@1.0.0: PASS
  provenance: 9 record(s), 0 unsigned, head sha256:28cc45c15

Next: nothing — all dimensions verified.
```

### Scenario B — modify one dataset file → DATASET INTEGRITY FAILURE

```text
node -e "const fs=require('fs');const p='dataset/circle/00.png';const b=fs.readFileSync(p);b[b.length-1]^=0xff;fs.writeFileSync(p,b)"
```

Expected: exit `1`, `Dataset Integrity FAIL`, identifies exactly which file.
Real captured output:

```text
  Overall: INTEGRITY VIOLATION
...
Findings:
  [BLOCKER] VG-DATA-001 dataset/circle/00.png: content changed: expected 5d44fa9fa0c6d01c5bf9a7372ff39f569e3103116361df4f32a33df382fcb5e4, got fdedef7a4f771def1c02c7d5a32a18c6584ef9abe45ea1bf23bc4998cd123853
```

### Scenario C — replace the model → MODEL INTEGRITY FAILURE

```text
node -e "const fs=require('fs');const p='model/demo-clf.safetensors';const b=fs.readFileSync(p);b[b.length-1]^=0xff;fs.writeFileSync(p,b)"
```

Expected: exit `1`, `Model Integrity FAIL`, rule `VG-MODEL-001`.

### Scenario D — edit pipeline code → PIPELINE INTEGRITY FAILURE

```text
node -e "require('fs').appendFileSync('pipeline.js','\nexport function tampered() {}\n')"
```

Expected: exit `1`, `Pipeline Integrity FAIL`, rule `VG-PIPE-001`.

### Scenario E — edit a provenance record (log tail rollback) with the live anchor → PROVENANCE INTEGRITY FAILURE

```text
node -e "const fs=require('fs');const f='.visionguard/provenance.log';const l=fs.readFileSync(f,'utf8').trim().split('\n');l.pop();fs.writeFileSync(f,l.join('\n')+'\n')"
```

Expected: exit `1`, `Provenance FAIL`, rule `VG-PROV-008` (the anchored head no longer matches).
`vision provenance --verify` shows chain detail; the anchor at `.visionguard/anchors/head.txt`
is what makes this detectable.

### Scenario F — edit prediction.json → OUTPUT INTEGRITY FAILURE with expected vs actual SHA-256

```text
node -e "const fs=require('fs');const p='outputs/prediction.json';const b=fs.readFileSync(p);b[b.length-1]^=0xff;fs.writeFileSync(p,b)"
```

Expected: exit `1`, `Output Integrity FAIL`, rule `VG-OUT-001` showing both hashes.
Real captured output:

```text
  Overall: INTEGRITY VIOLATION
...
Findings:
  [BLOCKER] VG-OUT-001 outputs/prediction.json: output file content does not match the recorded hash: expected c957f57dff9c4b8a716dab8e162b1b209d89932abef5125c7c2a581bbc616273, got a4994a93493f18270e38525d9a182fa5310f6a03c1e751f0c29c72c16a90e600
```

The JSON form (`vision verify --json`) carries the same data as structured fields:
`findings[].expected`, `findings[].actual`.

### Bonus Scenario G — edit a middle provenance record → PROVENANCE INTEGRITY FAILURE

```text
node -e "const fs=require('fs');const{canonicalJson}=require(process.argv[1]);const f='.visionguard/provenance.log';const l=fs.readFileSync(f,'utf8').trim().split('\n');const i=Math.floor(l.length/2);const r=JSON.parse(l[i]);r.metadata=Object.assign({},r.metadata,{tampered:true});l[i]=canonicalJson(r);fs.writeFileSync(f,l.join('\n')+'\n')" "$repo\src\visionguard\canonical"
```

> The module path is passed as an argument (`process.argv[1]`) instead of being inlined in the
> script text, because a JS string literal swallows backslashes (`'C:\Users\...'` becomes
> `C:Users...`). In bash use the forward-slash form of the same path.

Expected: exit `1`, `Provenance FAIL`, rules `VG-PROV-001` (the edited line's `record_hash` no
longer matches its content, and the chain link to the next record breaks) and `VG-PROV-005`
(the following record's parent link no longer resolves).

### Bonus Scenario H — forge a signature → PROVENANCE INTEGRITY FAILURE

```text
node -e "const fs=require('fs');const{canonicalJson}=require(process.argv[1]);const f='.visionguard/provenance.log';const l=fs.readFileSync(f,'utf8').trim().split('\n');const i=Math.floor(l.length/2);const r=JSON.parse(l[i]);const b=Buffer.from(r.signature,'base64');b[0]^=0xff;r.signature=b.toString('base64');l[i]=canonicalJson(r);fs.writeFileSync(f,l.join('\n')+'\n')" "$repo\src\visionguard\canonical"
```

Expected: exit `1`, `Provenance FAIL`, rule `VG-PROV-002` (`signature does not verify`).
An *unregistered* contributor is rejected with `VG-PROV-003` (covered by
`tests/unit/visionguard/security.test.js`).

### Bonus Scenario I — the same rollback WITHOUT an anchor → INCOMPLETE, never VERIFIED

```text
node -e "const fs=require('fs');const f='.visionguard/provenance.log';const l=fs.readFileSync(f,'utf8').trim().split('\n');l.pop();fs.writeFileSync(f,l.join('\n')+'\n')"
node -e "require('fs').rmSync('.visionguard/anchors/head.txt')"
```

Expected: exit `3`, `Overall: INCOMPLETE`, `Provenance: UNANCHORED` — contrast with scenario E.
Without an out-of-band anchor, rollback cannot be distinguished from an intact shorter history;
the tool must never claim `VERIFIED` here, and does not.

### Bonus Scenario J references (covered by the permanent security suite)

`tests/unit/visionguard/security.test.js` additionally asserts: stripped signature → `UNSIGNED`
(exit 3, `VG-PROV-009`), key substitution → `VG-PROV-003`, record replay → `VG-PROV-006`,
hostile filenames, path traversal, JSON depth bombs, and unanchored rollback. The runner above
covers the jury-facing subset A–I.

---

## 5. Cleanup

```powershell
Set-Location $repo      # then:
Remove-Item -Recurse vg-demo, vg-demo-*     # any scenario copies you created
```

The automated runner leaves its artifacts in a temp directory (path printed at start) for
inspection; delete it when finished. `scripts/visionguard-sih.js` never writes inside the repo.

---

## 6. Scenario → requirement mapping

| Prompt scenario | Demo scenario | Verdict | Evidence |
|---|---|---|---|
| Everything valid → VERIFIED | A | `VERIFIED`, exit 0 | six dimensions PASS, anchored |
| Modify dataset file | B | `INTEGRITY VIOLATION`, exit 1 | `VG-DATA-001`, file + expected/actual hash |
| Replace the model | C | `INTEGRITY VIOLATION`, exit 1 | `VG-MODEL-001` |
| Edit prediction.json | F | `INTEGRITY VIOLATION`, exit 1 | `VG-OUT-001`, expected vs actual SHA-256 |
| Edit a provenance record | G (content edit), E (tail rollback) | `INTEGRITY VIOLATION`, exit 1 | `VG-PROV-001`, `VG-PROV-008` |
| Forged/unregistered contributor | H (+ security suite) | `INTEGRITY VIOLATION`, exit 1 | `VG-PROV-002` / `VG-PROV-003` |
| Rollback with vs without anchor | E vs I | exit 1 vs exit 3 | `VG-PROV-008` vs `UNANCHORED` |
| (extra) pipeline tampering | D | `INTEGRITY VIOLATION`, exit 1 | `VG-PIPE-001` |
