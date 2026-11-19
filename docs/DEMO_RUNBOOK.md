# Everwell Health Portal - demo runbook (Zero Trust academic demonstration)

Branding: the interface is branded **Everwell Hospital** / **Everwell Health Portal** ("Compassionate Care. Trusted Access."). "Zero Trust" remains the name of the security architecture and of this academic project, so it stays in this document, the tests and the code comments. Details: `docs\UI_DESIGN.md` section 0.

Synthetic patients and demo accounts only. This is a course demonstration, **not** a production medical system and **not** production-ready.
Status words used below mean exactly one thing each: **implemented** (code exists), **compiled**, **tested** (an executed test in `tests\e2e` passed - see the matrix), **demonstrated** (shown by hand in a browser). Anything not yet run is marked **NOT RUN**.

## 1. What is running

```
phone / browser --HTTPS--> TLS edge (Java, only public entry point, 9443; loopback HTTP 8080)
                              |  adds the real client address + per-run edge key, relays only /api /ctl /admin
                              v
                          PEP (C++, 127.0.0.1:5000)  --internal key--> PDP (Java, https 127.0.0.1:8443)  <--HMAC heartbeats-- posture agent (C++, laptop)
                              |  forwards only after an ALLOW, with PEP-signed identity claims
                              v
                          protected API (Java, https 127.0.0.1:9000)  ->  SQLite (run folder, WAL)
```
Every protected request goes through one decision function in the PDP: token (device-bound) -> server-side session state -> account lock / idle / absolute timeout -> known endpoint -> role -> device posture -> network change -> patient scope (assignment / ward / break-glass) -> risk score -> step-up PIN. Denied or suspicious requests add penalty points to the **session**; at the threshold the server revokes the session and locks the account for a few minutes. The policy (bands, thresholds, penalties, network and posture rules) is editable by the security administrator at runtime and every change is audited.

| Signal | Where it comes from | Honest label |
|---|---|---|
| Laptop firewall, antivirus presence | signed posture agent on the laptop | **measured** (antivirus = "Security Center lists a product", not proof of real-time protection) |
| Phone: HTTPS, installed (standalone), online, connection type | the web page | **self-reported** (a page can lie; shown as such) |
| Phone: screen lock, OS patch level, device protection | cannot be read by a browser | **simulated** switches, always labelled "simulated" |
| Network address | the edge (real peer address); the demo can *simulate* another one | **measured** / **simulated** |

## 2. Start and stop (all on the laptop, nothing here changes a Windows setting)

```
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\demo\demo.ps1 -Action setup
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\demo\demo.ps1 -Action build
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\demo\demo.ps1 -Action start
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\demo\demo.ps1 -Action status
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\demo\demo.ps1 -Action stop
```
* `setup` creates a **new disposable run folder** under `%LOCALAPPDATA%\zt-demo\runs\<time>` with fresh secrets, a fresh database, fresh demo accounts. The live database in `db\` is never opened.
* `start` also creates the demo CA (once) and this run's server certificate. Do not pipe or redirect the output of `start` in a terminal you reuse (the servers inherit the pipe).
* The public sign-in screen shows no account, user name or role. Demo user names, passwords and step-up PINs are only in `<run folder>\demo_credentials.txt` (the path is the first line printed by `setup`; `%LOCALAPPDATA%\zt-demo\current.txt` holds it too): the private presenter sheet. Keep that file private. (This runbook names the four demo user names for the presenter; it contains no password or PIN.)
* Sign-in screen: two device choices, **"This browser"** (posture self-reported by the page; screen lock, OS patch level and device protection simulated; the page tells the server whether it is a desktop, phone or tablet browser from its user agent, and the server records only those three names) and **"Registered laptop"** (firewall and antivirus measured by the signed posture agent; offered only on the laptop that runs the agent, and the computer name is never shown). The footer says "Secure connection (HTTPS)" only when the page really was loaded over HTTPS; over plain HTTP it says so (checked in rows L4 and L5).
* On the laptop use `http://127.0.0.1:8080/` (loopback only). `https://localhost:9443/` also works but desktop browsers show a certificate warning because the demo CA is deliberately **not** installed in Windows.

| Account | Role | What it must (not) be able to do |
|---|---|---|
| `dr_alice` | Doctor | read/export the records of assigned patients (101, 102) only; anything else is denied by the server; emergency (break-glass) access with a justification: **read-only** (summary and clinical record, never the export), **one patient**, **only in the sign-in that asked for it**, for the approved time |
| `nurse_bob` | Nurse | patients of ward A only; clinical notes yes, **no diagnosis**, no export |
| `front_carol` | Receptionist | front-desk list (name, date of birth, ward, appointment) and **appointment management** (move the next appointment: `POST /api/patients/{id}/appointment`, receptionist only); **no clinical details**, even by direct API call |
| `sec_dan` | Security administrator | overview and risk alerts, sessions (revoke), devices and posture, access decisions, audit log, users (unlock) and emergency grants (revoke), policy; **no automatic clinical access** |

The interface (navy navigation, role screens, phone layout, accessibility notes, limits) is described in `docs\UI_DESIGN.md`; screenshots are in `docs\screenshots\`.

## 3. Putting the portal on the phone (realme UI 5.0, Android 14, Chrome)

The phone must reach **only** the edge. Two routes; the first needs no Windows change.

**Read-only check first:** `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\demo\phone_check.ps1` lists the laptop's Wi-Fi IPv4 and network category, the portal's listeners, the certificate (SAN coverage, the CA's name constraints, validity), a TLS handshake validated against the demo CA file only, the installability facts (manifest, icons, service worker) and the Windows Firewall rules (listed, never changed). It writes `<run folder>\reports\phone_check.txt`. It cannot say anything about the phone itself: **P1-P3 stay NOT RUN until you do them on the phone.**

The simplest first try needs **no certificate at all**: over the USB route `http://localhost:8080/` is a secure context for Chrome (installation and the service worker are allowed), and the sign-in footer then truthfully says the page was not loaded over HTTPS. Install the demo CA (3a) only if you want to show validated HTTPS (`https://localhost:9443/`).

### 3a. Optional: give the phone the demo CA (your action on the phone; the Windows trust store is not touched)
1. Laptop: `demo.ps1 -Action certs` (or `phone_check.ps1`) prints the CA's SHA-256 fingerprint; the CA file is `%LOCALAPPDATA%\zt-demo\ca\ca.crt`. Copy `ca.crt` to the phone's Download folder (USB cable, file-transfer mode) or any channel you trust.
2. Phone: Settings, then search for **CA certificate**. The menu names differ between realme UI versions (typically Settings > Password & security > System security > Encryption & credentials; stock Android 14: Settings > Security & privacy > More security settings > Encryption & credentials) > **Install a certificate > CA certificate** > "Install anyway" > pick `ca.crt`. (Android asks for a screen lock if none is set.)
3. Check Trusted credentials > User > "ZT Demo Root CA": its SHA-256 fingerprint must equal the one the laptop printed.
4. After the demo, remove it there again. The CA is **name-constrained** (localhost, loopback, private ranges and this machine's subnet at the time it was created), valid 14 days, and was created without the ability to issue sub-CAs; to destroy it on the laptop delete `%LOCALAPPDATA%\zt-demo\ca`.

### 3b. Route 1 - USB cable and Chrome port forwarding (no firewall, network or trust change on the laptop)
Phone, once: Settings > About device > Version > tap **Build number** 7 times (enter your screen lock); then Settings > Additional settings > Developer options > turn on **USB debugging** > OK. (If a menu is not where described, use the Settings search box.)
1. Connect the phone with a data cable. On the phone choose "Transfer files" if it asks for the USB mode, and tap **Allow** on "Allow USB debugging?" (tick "Always allow from this computer").
2. Laptop Chrome: open `chrome://inspect/#devices`, tick **Discover USB devices**; the phone should be listed. Click **Port forwarding...**, add `8080` -> `localhost:8080` and `9443` -> `localhost:9443`, tick **Enable port forwarding**, Done. Keep that tab open and the cable connected for the whole demo.
3. Phone Chrome: open `http://localhost:8080/` (no certificate needed) or, after 3a, `https://localhost:9443/`.
4. Sign in with the device choice "This browser". Chrome menu (three dots) > **Install app** (or *Add to Home screen*).
   * **NOT RUN** until you try it. Chrome's own installability check passes on the desktop (matrix W4), but whether Android creates a full "WebAPK" or only a shortcut for a private (localhost) origin is decided by Android/Google and is not tested here.
5. The installed app only works while the cable and port forwarding are active. Unplugging the cable is also a convenient way to show the offline page.
6. Evaluation mode on the phone (the risk, posture and network chips and the demonstration tools): open `http://localhost:8080/?evaluation=1` in a normal Chrome tab, not in the installed app.

**More reliable variant (adb, if you have Android platform-tools; the demo never downloads anything):** run `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\demo\phone_tunnel.ps1`. It keeps `adb reverse tcp:8080 tcp:8080` open whenever the phone (re)connects (it stops by itself after 4 hours; `-Remove` removes the tunnel; log `<run folder>\logs\phone_tunnel.log`). Then simply open `http://localhost:8080/` on the phone. **Do not combine it with `chrome://inspect` ("Discover USB devices" / port forwarding):** Chrome and the adb server compete for the phone's USB debugging interface; adb then lists no device while Windows still shows an "ADB Interface", and the tunnel disappears (seen on 2026-10-13: `adb` transport id 28 after 76 minutes). Close the inspect tab first. A tunnel exists on the USB cable only; nothing on the laptop's network, firewall or certificates changes.

If the phone does not appear in `chrome://inspect`: check the cable carries data, the USB mode is "Transfer files", the "Allow USB debugging" prompt was accepted (revoke USB debugging authorisations in Developer options and reconnect if it was dismissed), and that no other `adb` program is holding the phone. Older realme UI versions also have a **Disable permission monitoring** switch in Developer options that some guides ask for. If Windows needs the phone maker's USB driver, that is a download: nothing is downloaded without your approval.
If the phone shows `ERR_CONNECTION_REFUSED`: the stack is not running (`demo.ps1 -Action status`) or **Enable port forwarding** is off / the inspect tab was closed.

### 3c. Route 2 - same Wi-Fi (needs YOUR explicit approval of one firewall rule, and a Wi-Fi without client isolation)
Facts found by read-only checks: the Wi-Fi profile is **Public**; `java.exe` has inbound **Block** rules on Public; no rule exists for ports 8080/9443; the campus access point may isolate clients (unknown until tried). Nothing has been changed.
* Start the edge under `javaw.exe` (a different program than the blocked `java.exe`) and also on the Wi-Fi address:
  `demo.ps1 -Action start -EdgeUseJavaw -BindAddress <laptop Wi-Fi IPv4>`
* The one rule that would be needed (run by **you** in an *elevated* PowerShell, after you approve it; replace the phone's address; remove it after the demo):
  ```
  New-NetFirewallRule -DisplayName "ZT Demo Edge 9443 (temporary)" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 9443 -Program "C:\Program Files\Java\jdk-25\bin\javaw.exe" -RemoteAddress <PHONE-IP> -Profile Public
  Remove-NetFirewallRule -DisplayName "ZT Demo Edge 9443 (temporary)"
  ```
* Phone Chrome: `https://<laptop Wi-Fi IPv4>:9443` (after 3a). The certificate already lists the laptop's current IPv4 addresses; if the address changes, `start` issues a new server certificate (the phone keeps trusting the same CA).

## 4. Live demo script (about 12 minutes)

**Evaluation mode.** A clinical workspace shows no risk, posture or network information (that is the point of the role-specific interfaces). The steps below that show those decisions (7, 8, 10 and 4b) need **evaluation mode**: open the doctor's page as `http://127.0.0.1:8080/?evaluation=1` (on the phone: in a Chrome tab, not the installed app) and sign in; the navigation then has an "Evaluation mode (demonstration only)" group (My session, Demonstration tools), an "Evaluation mode" pill and the status chips. It works only while the security administrator leaves **Policy > Evaluation tools enabled** on (the default); switching it off removes evaluation mode from open pages, makes the server refuse the simulation requests and stop sending risk figures to non-administrators. Use a second window for the security console (`sec_dan`, normal address): watch the same session there while the doctor's window shows only plain words. **Give each role its own device on the laptop:** a browser stores its device id per address, so two sign-ins at the same address share one device record, and the simulated posture is stored on that record (`DeviceService`), so a change made for the doctor applies to every session on the same device, the administrator's included. Use, for example, the installed app (address `127.0.0.1`) for the console and a normal Chrome tab at `http://localhost:8080/?evaluation=1` for the doctor (a different address, so a different device), or an Incognito window, or the phone for the doctor.

| # | Do this | The evaluator sees | Where it is tested |
|---|---|---|---|
| 1 | Phone: sign in as `dr_alice` (device choice "This browser") | a clinical workspace with no status strip: the menu button (navigation drawer), the account button (avatar), "Next visits" and exactly patients 101 and 102 as cards | groups B, A12, W5, L6, M, RU1 |
| 2 | Open Grace Kim (101) | patient banner; Diagnosis, Medication, Care notes; "Export clinical summary" (PIN) shows synthetic identifiers masked by default | B, UI3 |
| 3 | "Open a patient by ID" 103 (not assigned) | "Patient not on your list" in plain words (no code, no technical detail, no risk figure; a number that does not exist gets the same answer); emergency access offered with its scope | B, W7, UI3, RU4, X4 |
| 4 | Emergency access: justification (>= 20 chars; for the XSS point type `<img src=x onerror=alert(1)>` plus some words), tick the confirmation, step-up PIN | amber banner "Emergency access - read only" with a live countdown, record shown, **no export**; it ends by itself and the record is refused again; the administrator sees it | E, BG1-BG6, U5 |
| 5 | Laptop (or second tab): `front_carol` -> Patient registry -> Appointments -> Reschedule | the new time is stored by the server and audited; no clinical word, field or button anywhere; a clinical request made directly against the API is refused by the **server** (role_denied, tested in X1 and R7) | T1-T9, U6, UI1, RU3, X1 |
| 6 | `nurse_bob`: ward-A patient, then id 102 (ward B) | medication and care notes only, no diagnosis; "Patient not on your ward" | B, UI2, RU2, X5 |
| 7 | Doctor in **evaluation mode** (see below) > Demonstration tools > Network change > "Different subnet" > Apply and re-evaluate | card "Step-up verification required", chip "Network: Changed (simulated)"; "Enter PIN and re-evaluate" -> "Access allowed after step-up verification", chip "Network: Unchanged (simulated address)" (the baseline now is the simulated address; test U2). "Same subnet" changes nothing | C, U2, RU11 |
| 8 | Device posture > switch "Screen lock" off > Apply and re-evaluate; then "OS patches" off too | chip "Desktop browser - Unhealthy", card "Step-up verification required"; then "Access denied" with the risk reason; "Reset simulated signals" restores the chip to "Desktop browser - Unknown" (a browser is never "healthy": nothing about it is measured) | C, U1, RU9 |
| 9 | Laptop posture: `demo.ps1 -Action agent -AgentArgs --fake-firewall-off` (then `-Action agent` again) | laptop device degraded, "agent mode = SIMULATED" (shown with the dashed *Simulated* badge); the real Windows Firewall is never touched | C |
| 10 | Evaluation mode > Demonstration tools > "Send 5 restricted requests" | risk climbs Low -> Elevated -> High, then the screen shows "Session ended" / "Session revoked" with the reason, the final risk level and the account lock (outside evaluation mode a clinical user sees only "Your session was ended for security reasons", RU14) | D, U3, RU14 |
| 11 | Try to come back: reload, second tab, sign in again, replay the old token | sign-in screen only; sign-in refused while locked; old token -> `401 session_revoked` | D, W9-W11, U3 |
| 4b | (optional) With the emergency grant active: try "Export" in the evaluation-mode Demonstration tools for that patient; open the same patient from a second sign-in of the doctor | export refused (`export_not_permitted`); the second sign-in does not inherit the grant | BG2, BG4 |
| 12 | `sec_dan` (laptop): Overview (risk alerts), Sessions, Access decisions, Audit log, Devices & posture, Users & access, Policy | counters and alerts with the time they were read (server clock), sessions with device and network evidence and its time (Revoke a live one: that user's screen shows "Session ended" by itself), every decision and event ("Network changes" filter), devices as Verified / Unhealthy / Stale / Unknown / Simulated with the age of the last report and the Measured / Self-reported / Simulated badges, accounts (Unlock) and emergency grants (Revoke), the live policy; change a value (PIN) -> audited; the justification from step 4 is shown as inert text (nothing executes) | F, UI4, U4 |

Defaults to know: allow below 40, step-up 40-69, deny from 70 (request risk); revoke threshold 60 (session risk: Low below 25 %, Elevated from 25 %, High from 60 % of it); lockout 5 minutes; a denial costs 5-25 points depending on its kind (the Policy screen lists them); token 90 s (renewed by the page every ~54 s); idle timeout 15 minutes (renewals and heartbeats do **not** count as activity); emergency access 15 minutes.

## 5. Tests
```
powershell -NoProfile -ExecutionPolicy Bypass -File tests\e2e\run_e2e.ps1            # default groups A,W,L,B,C,D,E,F,T,M,BR,X,RU; needs the stack running
powershell -NoProfile -ExecutionPolicy Bypass -File tests\e2e\run_e2e.ps1 -Groups 'A,W'
powershell -NoProfile -ExecutionPolicy Bypass -File tests\e2e\run_e2e.ps1 -Groups 'A,W,L,B,C,D,E,F,R,T,M,U,BR,X,RU'   # the complete suite (run it as a background task with a log file)
powershell -NoProfile -ExecutionPolicy Bypass -File tests\e2e\build_role_matrix.ps1   # after a full run that included B and R: role-by-role matrix
powershell -NoProfile -ExecutionPolicy Bypass -File tests\e2e\run_screenshots.ps1 -Set core   # screenshots to docs\screenshots
```
Groups: **A** edge/TLS/installability, **W** the web app in headless desktop Chrome (service worker, caches, storage, offline page, CSP, Chrome's installability check, the Everwell names in Chrome's parse of the manifest), **BR** the Everwell branding (static scan, manifest, icon pixels, sign-in page, every screen of all four roles, offline page, public hospital information), **L** the sign-in screen and the four role sign-ins, **B** roles and least privilege, **C** posture and network, **D** risk and revocation, **E** break-glass, **F** evidence and hygiene, **R** the role-by-role review (what each role sees and gets back, tampering, plus the sub-groups **BG** emergency access, **AP** the protected app on its own, **UI** what the screens show), **T** appointment management through the front door, **M** phone-width layout and mobile usability (emulation in desktop Chrome), **U** scenarios through the real screens (posture, network, risk, revocation, emergency access, appointments), **X** the authorization matrix (every endpoint x every role, refused requests change nothing, no patient-existence oracle, need-to-know of risk figures with the evaluation tools on and off, device labels, sign-out; direct API calls), **RU** the role-specific interfaces in real Chrome (clinical workspaces without security monitoring, plain-language states, the security console with its evidence, routes of other roles, device labels, unknown and stale evidence, evaluation mode, the account menu, session notices and end-of-session screens). The matrix is written to `<run folder>\reports\scenario_matrix.md/.json`. Rows **P1-P3** (the phone) stay NOT RUN until done on the phone.

## 6. Limits you must say out loud
* JUnit tests of the original code were never run; the application is **not proven correct or secure**; the tests are samples, not a proof.
* Passwords/PINs use salted PBKDF2-HMAC-SHA256 (310,000 iterations) from the JDK, **not** Argon2id.
* The internal TLS hops (PEP -> PDP, PEP -> protected API) are loopback only and the C++ client does not validate their self-signed certificates.
* A browser cannot measure antivirus, screen lock or patch level: on the phone those are simulated; the laptop's firewall/antivirus-presence come from the agent.
* Over the USB route every request reaches the edge from the laptop's own loopback address, so the server cannot tell the phone from the laptop by address: the sign-in screen offers "Registered laptop" on the phone too. Use "This browser" on the phone (the network-change demo is simulated anyway).
* Role-by-role findings, fixes and the measured matrix are in `docs\ROLE_REVIEW.md`. The interface redesign and its limits are in `docs\UI_DESIGN.md`.
* **No real phone has been used for any test.** The 360 px results (group M, the phone screenshots) are emulation in desktop Chrome; installation, offline use and a live scenario on the phone (P1-P3) are NOT RUN. Screen-reader use was not tested.
* The shell and the API are served over HTTPS only when you use the edge and trust the demo CA; the plain HTTP listener exists on loopback for local tests and USB forwarding.
* CP3 Phase B of the earlier audit plan was **not** run and no deliberate crash test was executed.
* Phone installation and the offline page **on the phone** are NOT RUN until you try them.

## 7. Clean-up
`demo.ps1 -Action stop`; remove "ZT Demo Root CA" from the phone; delete the firewall rule if you created one; delete `%LOCALAPPDATA%\zt-demo\ca` when you no longer need the CA; the run folders under `%LOCALAPPDATA%\zt-demo\runs` can be deleted at any time.
