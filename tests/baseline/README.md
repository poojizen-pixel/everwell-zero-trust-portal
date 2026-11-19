# tests/baseline

Baseline of the LEGACY system (before any hardening), recorded in CP3. Nothing here describes the final system.

* `cp3_expectations.json` - the 30 frozen steps. Each has a REQUIREMENT (what your spec / the Stage 2 target demands) and a PREDICTION (what reading the
  legacy source says it will do). The file's SHA-256 is recorded in the Phase A manifest before anything runs; Phase B refuses to run if it changed.
* `cp3_results.json` / `cp3_results.md` - written by CP3 Phase B only (they do not exist until Phase B has run). Redacted: no password, PIN, token,
  session id, SSN or billing value is stored, only statuses, reasons, risk numbers, field names and counts. Phase B scans these files, the evidence and
  the program logs for synthetic patient data, issued secrets and credential shapes before it finishes, and reports category and location only.

How to read a result:

| Column | Meaning |
|---|---|
| Baseline verdict | PASS = the legacy system met the requirement; FAIL = it did not (a known defect, recorded, not fixed); OBSERVATION = no requirement exists yet |
| Predicted | what the frozen file predicted for the verdict |
| Prediction held | whether every predicted detail (status, risk number, reason text, timing) was observed. A "NO" means the code reading was wrong; it is reported, never edited away |

The scratch copy used for the baseline has 18 documented line changes (ports and paths, two loopback binds, and a terminate handler that avoids
Windows Error Reporting; see `scripts/cp3/patches.json`). It is NOT the unmodified legacy build.
