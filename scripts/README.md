# Build and test scripts

Everything here is for development and testing. Nothing in these scripts downloads anything, changes a system setting,
or starts a network listener. The built `pep_proxy.exe` and `agent.exe` are never run by them (they open network
connections), so they are only compiled and linked.

## Run them without changing any system setting

```text
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build.ps1
```

`-ExecutionPolicy Bypass` applies to that one process only.

## What was used (tested versions)

| Tool | Version | Needed for |
|---|---|---|
| Windows PowerShell | 5.1 | all scripts (they avoid newer syntax) |
| JDK (`javac`, `java`) | 25.0.1 (the only version tested) | building pdp, protected_app and DbTool; database tests |
| MinGW-w64 `g++` | 15.2.0, UCRT, C++17 (the only version tested) | building pep_proxy and agent; C++ tests |
| Node.js | 24.18.0 (the only version tested) | only `check-secrets.ps1` and the scanner suite |
| jars already in `lib\` | sqlite-jdbc 3.46.1.3, gson 2.11.0 | Java builds and `DbTool` |

The JUnit console jar is NOT in `lib\` yet (it needs dependency gate G1), so Java unit tests are reported NOT RUN.

## Scripts

| Script | Purpose | Exit code |
|---|---|---|
| `build.ps1` | Builds `tools`, `pdp`, `protected_app`, `pep_proxy`, `agent` into `build\` (the existing `out\` folders and binaries are not touched) | 0 all built, 1 a component failed, 2 a tool is missing |
| `run-tests.ps1` | Runs the suites `cpp`, `scanner`, `dbtool`, `scan-options`, `backup-options`, `harness-selfcheck`, `java-junit` and prints PASS / FAIL / NOT RUN per suite | 0 no FAIL, 1 a FAIL (or a NOT RUN with `-Strict`), 2 harness error |
| `check-secrets.ps1` | Runs the secret scanner over the project with redacted output; `-SelfTest` checks the scanner itself | 0 clean, 1 confirmed findings, 2 error, 3 NOT RUN (no Node.js) |
| `new-disposable-db.ps1` | File copy of a verified database (the `.db`, `-wal` and `-shm` files) into a work folder outside the repository, verified by SHA-256 | 0 ok, non-zero refused or failed |
| `backup-db.ps1` | SQLite online backup (`VACUUM INTO`) of a database, verified table by table | 0 verified, non-zero refused or failed |

Verdicts are exactly `PASS`, `FAIL` or `NOT RUN`. A `NOT RUN` is never counted as a pass.

## Safety rules built into the scripts

* The project's live `db\` folder is refused as a source for `new-disposable-db.ps1` and `backup-db.ps1`
  (`backup-db.ps1 -AllowProjectDb` is meant for a deliberate backup of the live database later. It is tested only inside a
  throw-away fixture repository by the `backup-options` suite, never against the real project database.)
* The `-DbSource` folder passed to `run-tests.ps1` is only hashed and file-copied. SQLite only ever opens the disposable copy.
* Disposable databases and other scratch files go to `%TEMP%\zt-his-work` (or `-WorkRoot` / `ZT_WORK_ROOT`), never inside the repository.
* A database file copy must include the `-wal` file: it can hold committed data that is not yet in the `.db` file.
* The secret scanner never writes inside the folder it scans, except under `<root>\build`, and never prints a secret value.

## Build output (`build\`)

`build\java\<component>` (classes), `build\cpp\*.exe`, `build\cpp\tests\*.exe`, `build\tools\DbTool.class` and
`build\reports\` (build and test reports). The built executables need `libstdc++-6.dll` and `libgcc_s_seh-1.dll`
(the agent also `libwinpthread-1.dll`) from the MinGW `bin` folder, which must be on `PATH`.

## CP3 baseline scripts (`scripts\cp3`)

They record how the LEGACY system behaves (a baseline, not a fix). Everything runs on a patched scratch copy outside the repository.

| File | Purpose |
|---|---|
| `Run-Cp3.ps1 -Phase A` | Prepares and verifies the scratch copy: tree from the verified backup, build (compilers only), disposable database copies, harness self-checks. It never starts a listener or a legacy program |
| `Run-Cp3.ps1 -Phase B -RunDir <run folder> -ConfirmStartListeners` | Starts API, PDP, PEP and agent on 127.0.0.1 only, runs the 30 frozen steps, stops everything, verifies. Needs separate approval. **Not run yet** |
| `New-Cp3Tree.ps1`, `patches.json` | Builds the patched tree from the backup; 18 exact-line edits, each checked three independent ways |
| `Test-Cp3Harness.ps1` | Self-checks of the harness (fixtures, a harmless sleeper, a no-socket dry run against a model of the stack) |
| `Stop-Cp3.ps1` | Emergency stop: only processes recorded in `pids.tsv` whose pid, start time and image path still match |
| `cp3_lib.ps1`, `cp3_proc.ps1`, `cp3_engine.ps1`, `cp3_fake_stack.ps1` | helpers, process/Job Object/listener audit, scenario engine, test-only model (the model is never loaded by `Run-Cp3.ps1`) |
| `tools\SeedTestUsers.java` | Fixture checks and a credential reset on a DISPOSABLE database copy; secrets arrive on stdin and are never printed |

Safety rules: only programs inside the scratch tree may be started; the live `db\` files are only hashed and size/time-checked; generated
credentials exist in memory only; results go to `tests\baseline\` (redacted) and to the evidence folder.

Stop conditions of Phase B (each one stops the run at once; nothing is retried, repaired or hidden):

* **Run-state monitor** (before every request and at the start of every slice of at most one second of every wait, including the waits for a listener or a
  heartbeat): a recorded process that should be running has exited (reported with its exit code); a process is in the Job Object that the run did not start and
  record (only the system `conhost.exe` of a recorded process is tolerated); a recorded running process is not in the Job Object; a live database file changed;
  a test-port listener is not on 127.0.0.1; the time limit was exceeded. Planned exits are allowed only for the agent at step T13 and for the PEP at P1 and P2,
  between a begin and an end call; ending the window needs the role to be running again, and the PEP's exit code must be the planned 99.
* **Listener / connection audit** (process-attributed, one read of the TCP table): after every start, after the agent restart, after every PEP restart,
  before shutdown, about every 5 seconds in between (a sample) and in any case before every 10th request. A listener that is not on 127.0.0.1, a connection of a recorded or job process whose remote
  end is not 127.0.0.1, an audit source that cannot be read, or a running server role that is not seen listening on its port: the run stops.
* **After shutdown** (gate B7): every stop result is `stopped` or `already-gone`; every recorded process is shown to have exited; no job leftover; nothing
  running from the run folder or listening on the test ports; the live database, the original files, the project, the protected backup/evidence set and the
  scratch tree are unchanged; the disposable database passes its integrity check. Nothing is deleted, restored or overwritten to make a check pass.
* **Results** (gate B8): evidence, test results and program logs are scanned for synthetic patient data, issued secrets and credential shapes. A report names
  the category, the file and the line, never the matched value.

## Not exercised yet

* Everything in the `java-junit` suite (it needs gate G1).
* The built `pep_proxy.exe` and `agent.exe` have only been compiled and linked, never started. The same holds for the patched scratch builds made by CP3 Phase A.
* CP3 Phase B (starting the scratch programs, sending the scenario requests, stopping them) has not been run; its process-starting code is only exercised with a harmless sleeper and a model.
* `backup-db.ps1 -AllowProjectDb` against the real project database: deliberately never run; only the fixture suite exercises it.

## Tests

* C++: put `test_*.cpp` in `tests\cpp\`, include `mini_test.h`, write `MT_TEST(name) { MT_CHECK_EQ(a, b); }` and end the file with `MINITEST_MAIN()`.
* `tests\cpp\test_selfcheck_fail.cpp` fails on purpose and is compiled only with `run-tests.ps1 -InjectFailure`.
* The secret scanner has one deliberately narrow waiver for public test vectors. It applies only when ALL of these hold:
  the line has a comment (`//`, `#`, `--` or `/*`) containing `secret-scan: allow` followed by a reason; the file is inside a folder
  named `tests`; and the flagged item is an unnamed hex literal of 40, 64, 96 or 128 characters. It never waives a secret-named
  constant, a key header, a token format, a credential hash, a demo credential, a base64 literal or a hex literal of another length.
  Waived items are still listed as ALLOWED and counted in every summary. Twelve self-test controls try to abuse the marker, and a
  mutation test showed they fail against wider waivers.
