# Everwell Health Portal

A small hospital portal built as a Zero Trust demonstration for a university course (Advanced Programming and Database Systems). The idea behind Zero Trust is that being signed in is not enough: every request is checked again, using what the system knows at that moment, before any patient data is returned.

All patient data in this project is made up. It is a demonstration, not a production system. "Everwell Hospital" is an invented name and has not been checked against real organisations or trademarks.

## How it works

A user signs in as one of four roles. From then on every request goes through the same path:

```
browser or phone -> TLS edge (Java) -> PEP (C++) -> PDP (Java) -> records service (Java) -> SQLite
                                                      ^
                                          posture agent (C++, on the laptop)
```

The PDP (policy decision point) looks at the role and whether the patient is assigned to this user, the state of the device, whether the network address has changed, and a risk score that the session builds up. The answer is allow, ask for the step-up PIN, deny, or end the session. Refused requests add to the risk score. Past the limit the session is revoked and the account is locked for five minutes. Every decision goes into an audit log.

The four roles:

- **Doctor**: sees the patients assigned to them. For anyone else they can ask for emergency access, which needs a written reason, is read-only, covers one patient and runs out after a while.
- **Nurse**: sees the patients on their ward, with medication and care notes but no diagnosis.
- **Receptionist**: sees names, dates of birth and appointments, and can reschedule an appointment. No clinical data.
- **Security administrator**: reads sessions, devices, decisions and the audit log, can revoke sessions, unlock accounts and change the policy. No patient data.

Doctors, nurses and receptionists normally see none of the security machinery. If the page is opened with `?evaluation=1` and the administrator has left the evaluation tools on, a clinical user also sees their own risk, device and network status and gets switches that simulate a network change or a weaker device. That is what the live demo uses.

Not every signal is measured. The laptop's firewall and antivirus state is read by a small signed agent. A phone's browser cannot read its screen lock, patch level or protection status, so those are simulated switches and are labelled that way. A browser is never shown as "verified".

## Running it

This only works on Windows. You need:

- PowerShell 5.1
- a JDK (tested with 25.0.1, other versions not tried)
- MinGW-w64 `g++` on the PATH (tested with 15.2.0, UCRT)
- Git for Windows, for the `openssl.exe` that makes the demo certificates
- Chrome, and Node.js 24 if you want to run the browser tests

Then, from the project folder:

```
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\demo\demo.ps1 -Action setup
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\demo\demo.ps1 -Action build
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\demo\demo.ps1 -Action start
```

Open `http://127.0.0.1:8080/`. This address only works on the same machine. `https://localhost:9443/` also works, but the browser will warn about the certificate: it is signed by a demo certificate authority that is deliberately not installed in Windows. `-Action status` shows what is running and `-Action stop` stops it. The scripts download nothing and do not change any Windows firewall, network or certificate setting.

Each `setup` makes a fresh run folder under `%LOCALAPPDATA%\zt-demo\runs\<time>` with its own secrets, database and demo accounts. The accounts are `dr_alice` (doctor), `nurse_bob` (nurse), `front_carol` (receptionist) and `sec_dan` (security administrator). Their passwords and PINs are random per run and are written only to `demo_credentials.txt` in that run folder, never to this repository.

[docs/DEMO_RUNBOOK.md](docs/DEMO_RUNBOOK.md) has a 12-minute demo script, the steps for opening the portal on a phone over a USB cable, and the known limits.

## Tests

`tests\e2e\run_e2e.ps1` drives the running portal through the API and through headless Chrome. The full run takes about 13 minutes. The last complete run was on 13 October 2026, on a freshly built run folder: 249 checks passed, none failed, 3 were not run. The three that were not run are the phone checks (installing the app, the offline page and a live scenario on a real phone). Nobody has run them as test rows. These tests are samples and do not prove the system correct or secure.

`scripts\run-tests.ps1` runs the older unit-level suites (C++, the database tool, the secret scanner). The Java JUnit tests have never been run, because the JUnit jar is not in `lib\`.

## What is where

| Folder | Content |
|---|---|
| `web/` | the browser front end (a single-page app that can be installed as a PWA) |
| `edge/` | TLS front door, the only part meant to be reachable from outside |
| `pep_proxy/` | policy enforcement point (C++) |
| `pdp/` | policy decision point (Java) |
| `protected_app/` | records service (Java) |
| `agent/` | posture agent (C++) |
| `shared/` | C++ code used by the agent and the proxy |
| `db/` | SQL schemas; `schema_demo.sql` is the one the demo uses |
| `scripts/` | `demo/` runs the demo; the other scripts build and test the project |
| `tests/` | end-to-end tests (`e2e/`) and C++ unit tests (`cpp/`) |
| `docs/` | runbook, interface notes, role review, screenshots |
| `slides/` | presentation files |
| `lib/` | the Java libraries (SQLite driver, Gson) |

## Not done, or not proven

- The tests do not prove the system correct or secure, and it is not ready for production use.
- Passwords and PINs are hashed with salted PBKDF2-HMAC-SHA256, not Argon2id. The calls between the internal services use TLS on the loopback interface only, and the C++ proxy does not check their self-signed certificates.
- Over the USB tunnel the portal sees every request coming from the laptop's own address, so it cannot tell when the phone's real network changes. The network change in the demo is a simulated address, clearly labelled. The decision the server makes about it is real.
- Database queries use parameters, but no test tries SQL injection. The schema has no triggers. The audit table is append-only only because the code never edits it.
- No real phone was used in any automated test, and no screen reader was used.

## Older material

The project started in September as a Zero Trust access simulator. Its code is kept in the `legacy_src` folders, `db/schema.sql`, `dashboard/` and `slides/Zero_Trust_Access_Simulator.pptx`; `scripts/cp3/` belongs to an earlier audit phase. None of it is needed to run the demo. The old simulator's made-up demo accounts use a placeholder password and PIN that are written in plain text in `db/schema.sql` and on slide 7 of that deck. They only work against the old simulator, and the Everwell demo does not use them.

## Third-party code

`lib/sqlite-jdbc-3.46.1.3.jar`, `lib/gson-2.11.0.jar` and `shared/include/json.hpp` (JSON for Modern C++ by Niels Lohmann) keep their own licences. This repository has no licence of its own.
