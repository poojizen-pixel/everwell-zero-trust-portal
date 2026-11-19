# Everwell Health Portal - Zero Trust academic demonstration

A course project (Advanced Programming and Database Systems): a small hospital portal in which **every request is checked by a Zero Trust policy decision point**.
**Synthetic patient data only. This is a demonstration, not a production medical system, and it is not production-ready.**
"Everwell Hospital" is a fictional name; it was not checked against real organisations or trademarks.

Status words used in this repository: **implemented** (the code exists), **compiled**, **tested** (an executed test row passed), **demonstrated** (shown by hand), **NOT RUN** (not executed).

## What it does

```
phone / browser --HTTPS--> TLS edge (Java, the only public entry point)
                              -> PEP (C++) -> PDP (Java, one decision pipeline) <-- signed posture agent (C++, laptop)
                                              -> protected app (Java) -> SQLite
```

For every request the PDP checks: token and session, account lock and timeouts, known endpoint, role (RBAC), device posture, network context, patient scope
(assignment, ward, time-limited emergency access), a risk score and, when the policy asks for it, a step-up PIN. A refused request adds risk to the session;
at the threshold the server revokes the session and locks the account for a few minutes. Every decision is written to an audit log.

Four roles: **doctor**, **nurse**, **receptionist**, **security administrator** (the security console). A clinical workspace shows clinical work only; the
risk, device and network details appear in the security console and, for a demonstration, in an "evaluation mode" (`/?evaluation=1`).

Honest labels: the laptop's firewall and antivirus presence are **measured** by the signed agent. A browser can only report about itself, so a phone's other
signals are **self-reported** or **simulated** and are shown that way. A browser is never shown as "verified".

## Requirements (Windows only)

- Windows 10/11 with PowerShell 5.1
- a JDK (tested with 25.0.1; other versions were not tried)
- MinGW-w64 `g++` on PATH (tested with 15.2.0, UCRT / posix / seh)
- Git for Windows (its `openssl.exe` creates the demo certificates)
- Chrome; Node.js 24 only to run the browser-driven tests

The scripts download nothing. They never change Windows firewall, network or certificate-store settings (the demo CA is kept in files only; installing it on a phone is a user action).

## Run it

```
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\demo\demo.ps1 -Action setup
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\demo\demo.ps1 -Action build
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\demo\demo.ps1 -Action start
```

Then open `http://127.0.0.1:8080/`. `-Action status` shows what runs, `-Action stop` stops it. Each `setup` creates a **disposable run folder** under
`%LOCALAPPDATA%\zt-demo\runs\<time>` with fresh secrets, a fresh database and fresh demo accounts. The user names, passwords and step-up PINs are only in that
run folder's `demo_credentials.txt` - never in this repository.

The step-by-step live demo (about 12 minutes), the phone route over USB and the limits are in [docs/DEMO_RUNBOOK.md](docs/DEMO_RUNBOOK.md).
`scripts\demo\phone_check.ps1` is a read-only diagnostic for the phone route.

## Tests

With the stack running: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\e2e\run_e2e.ps1 -Groups 'A,W,L,B,C,D,E,F,R,T,M,U,BR,X,RU'` (about 13 minutes;
run it as a background task with a log file). Last complete run (2026-10-13, the author's laptop, freshly built run folder): **PASS 249, FAIL 0, NOT RUN 3**.
The three NOT RUN rows (P1-P3) are the installation, the offline page and a live scenario on a physical phone. The tests are samples, not a proof of
correctness or security. JUnit tests of the original code were never run.

## Documents

| File | Content |
|---|---|
| [docs/DEMO_RUNBOOK.md](docs/DEMO_RUNBOOK.md) | start and stop, the phone, the live demo script, limits |
| [docs/ROLE_UX_AUDIT.md](docs/ROLE_UX_AUDIT.md) | the role-by-role dashboard and Zero Trust UX correction, results |
| [docs/ROLE_REVIEW.md](docs/ROLE_REVIEW.md) | role-by-role review and the measured matrix |
| [docs/UI_DESIGN.md](docs/UI_DESIGN.md) | the interface, accessibility notes, test history, limitations |
| [docs/screenshots/](docs/screenshots/) | screenshots from 2026-10-12, taken before the role correction (see its README) |
| [slides/](slides/) | presentation files |

## Limits you must say out loud

- Not production-ready; the application is not proven correct or secure.
- Passwords and PINs use salted PBKDF2-HMAC-SHA256, not Argon2id. The internal TLS hops are loopback only and the C++ client does not validate their self-signed certificates.
- A browser cannot measure antivirus, screen lock or patch level; on a phone those are simulated switches.
- Over a USB tunnel every request reaches the portal from the laptop's own loopback address, so a real network change of the phone cannot be observed;
  the demonstration uses a clearly labelled simulated network switch (the decision itself is real).
- Queries use parameters, but no dedicated SQL-injection test was run (NOT RUN). There are no database triggers; the audit table is append-only by application discipline only.
- No physical phone was used in any automated test; no screen reader was used.

## Third-party components

`lib/sqlite-jdbc-3.46.1.3.jar`, `lib/gson-2.11.0.jar` and `shared/include/json.hpp` (JSON for Modern C++, nlohmann) keep their own licences.
This repository itself has no licence file.
