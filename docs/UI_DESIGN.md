# Portal interface: design note (2026-10-12 redesign, role-specific interfaces 2026-10-13)

Academic demonstration, **synthetic patient data only**. This note describes the redesigned web interface (`web/`), how it keeps the security
behaviour of the server, and what has and has not been verified. It does not claim production readiness.

The redesign was made **in place**: the same single-page app (`web/app.js`), the same server calls, the same service worker. No screen is a static
mock-up; every list, chart, decision and counter comes from the running servers. One server-side addition was needed for the receptionist's
appointment management (section 6).

**2026-10-13 role correction.** The first redesign showed the same security status strip and the same session, posture and demonstration screens to every
role. They were taken out of the clinical workspaces (sections 3-4 describe the result), the security console was given evidence, times and an exact
state vocabulary, and the server stopped sending security figures to roles that do not need them. The audit, the reasons and the tests are in
`docs/ROLE_UX_AUDIT.md`; this note describes the interface as it is now.

## 0. Branding (2026-10-12): Everwell Hospital

| Item | Value |
|---|---|
| Hospital name | **Everwell Hospital** (sign-in header bar, sidebar, the small hospital name above every page title, browser tab title `<screen> - Everwell Hospital`, offline page, `/api/public/info`) |
| Portal name | **Everwell Health Portal** (sign-in card, sidebar sub-line "Health Portal", manifest install name, `application-name` metadata) |
| Home-screen label | **Everwell** (manifest `short_name`, at most 12 characters so Android does not truncate it) |
| Tagline | "Compassionate Care. Trusted Access." (sign-in header bar, offline page, manifest and page descriptions) |
| Mark | a white medical cross inside a teal ring on deep navy, drawn by `scripts/demo/make-icons.ps1` with `System.Drawing` (no external assets): `icon-192.png`, `icon-512.png`, a full-bleed `icon-maskable-512.png` whose symbol stays inside the Android safe zone, and `favicon.png` |
| Kept on purpose | the discreet line "Academic demonstration - synthetic patient data only" on the sign-in screen and in the descriptions: the portal is a course demonstration and uses fictional data |

"Zero Trust" is still the name of the security architecture and of this academic project, so it stays in the developer documentation, security explanations, source comments, test names, audit evidence and technical identifiers (`zt_device_id`, the cache name `zt-shell-v4`, `X-ZT-*` headers, the certificate subjects of the demo CA, the legacy SOC console under `dashboard/`, the frozen CP3 scripts). It no longer appears in anything a user sees (test group BR scans the files and the rendered pages). The service-worker cache was renamed (`zt-shell-v3` with the branding, `zt-shell-v4` with the role-specific interfaces) so installed copies replace their cached shell, names and icons.

## 1. Visual system (`web/styles.css`)

| Element | Decision |
|---|---|
| Surfaces | light grey page (`#f3f5f8`), white panels with a 1 px border, 6 px corners, no shadows or gradients |
| Navigation | deep navy (`#0b2545`) sidebar on desktop, the same navigation as a slide-in drawer on phones; one restrained teal accent (`#0f766e`) for the primary button and the selected item |
| Type | system font stack, 15 px base (16 px form fields on phones), page title 20 px, panel titles 15 px, tables 13 px |
| Status | badges and chips always carry a word (Allowed, Step-up required, Denied, Session revoked, Verified, Unhealthy, Stale, Unknown, Simulated, Unavailable, Low/Elevated/High risk); colour never carries the meaning alone; "healthy" is never used for a state the evidence does not support |
| Provenance | three distinct badges: **Measured** (read by the signed laptop agent or timed by the server), **Self-reported** (stated by the web page), **Simulated** (dashed outline: a demonstration switch, not a measurement) |
| Components | one set for sign-in, navigation, buttons, inputs, segmented control, switches, tables, alerts, dialogs (native `<dialog>`), toasts, skeleton loaders, empty states |
| Tables | compact tables on desktop; the same markup turns into cards below 720 px (explicit ARIA roles keep the table semantics) |
| Motion | a 0.2 s drawer slide; everything is disabled under `prefers-reduced-motion` |

Constraints kept from the earlier version (and checked by tests): no HTML-parsing API anywhere (every server value is inserted as text), no inline
style attributes (the Content-Security-Policy forbids them; dynamic widths use a CSSOM-set custom property), token and PIN in memory only, only the
non-secret `zt_device_id` in `localStorage`, the service worker caches the static shell only.

## 2. Responsive behaviour

* Mobile first. Below 1024 px the navigation is a drawer: the menu button exposes `aria-expanded` / `aria-controls`, focus moves into the drawer, the page behind is `inert`, Escape or a tap on the dimmed page closes it and focus returns to the menu button; choosing a link navigates and closes it.
* From 1024 px the navigation is persistent. The top bar carries the page title and the **account button** (an avatar, at least 44 px, on every screen size); the status chips (session, network, device, risk) exist **only in evaluation mode** (section 4); there they sit on their own row under the title and wrap (a one-line top bar overflowed a 360 px phone and a 1024 px window, found by rows M3-M5 and M11 on 2026-10-13), shown in full from 1024 px and, on a phone, as the "Evaluation mode" pill plus the single risk chip.
* Touch targets are at least 44 x 44 px on phones and touch devices (buttons, links, inputs, switches, summaries, drawer links); form fields use 16 px text so phone browsers do not zoom.
* Patient screens are two-pane on desktop (list and chart) and one pane at a time on phones, with real URLs (`#/patients/101`) so the phone's Back button returns from a chart to the list.
* Verified at 360 px and 320 px (and 768, 1024, 1280, 1920 px) by test group **M** in desktop Chrome with phone **emulation**. That is not a real phone: **phone testing has not been done on a real phone** (rows P1-P3 stay NOT RUN).

## 3. Role screens

| Role | Navigation | Content |
|---|---|---|
| Doctor | My patients | assigned patients (search by name, ID or ward, open by ID), **Next visits**, patient banner, diagnosis, medication, care notes, export of the clinical summary (assigned patients only, masked identifiers); a patient who is not on the list shows one plain refusal (the same for a number that does not exist) and the **emergency access** request (read-only, one patient, this sign-in only, approved duration, justification and confirmation required); granted access shows an amber banner with a live countdown and drops the record by itself when time is up |
| Nurse | Ward patients | patients of the nurse's ward, **Next visits**, patient banner, medication and care notes only; no diagnosis, no export, no emergency access; another ward's patient (or a missing number) shows "Patient not on your ward" |
| Receptionist | Patient registry, Appointments | demographics and appointment only; **Reschedule** (date and time) calls the appointment endpoint; no clinical heading, field, button or navigation item anywhere. Registering a new patient is not part of this build (no endpoint exists, and adding one would be a new permission) |
| Security administrator (SOC) | Overview, Sessions, Devices & posture, Access decisions, Audit log, Users & access, Policy, My session | counters and **risk alerts** (locked accounts, active emergency access, elevated sessions, unhealthy devices, network changes, recent revocations), live session list with revoke, devices with evidence, every decision and audit event with filters, accounts (unlock) and emergency grants (revoke), the full editable policy with plain-language labels; never any patient name or clinical value |

Navigation is configured per role in one place (`NAV`) and a typed route that the role does not have falls back to the role's first screen; both are
conveniences, the server enforces every request. A clinical workspace has no security screen and the security console has no patient screen.

## 4. Zero Trust on screen

**Clinical roles (doctor, nurse, receptionist)** see security only when it needs them to act, in plain words, and never as a dashboard:

* the **step-up PIN** dialog ("Enter your step-up PIN to continue"), a **refusal** ("Patient not on your list", "Access unavailable on this device", ...), the amber **emergency access** banner with its countdown, the **offline** banner;
* **minimal session feedback** from the server's own limits: "You will be signed out soon" (with *Stay signed in*, which really counts as activity) shortly before the idle limit, "Maximum session length" shortly before the longest session ends, and an end-of-session screen that says what happened (revoked, expired, locked until a time);
* the **account menu** (top-bar avatar): name, role (and ward), when they signed in, the automatic sign-out and the longest session, the server's confirmation of the session, Sign out;
* no status chips, no risk, posture, network, threshold, policy or event wording, no technical detail or reference code, no device or network address.

**Security administrator (SOC)**: the console states what each screen measures and when its data was read ("Live - updated hh:mm:ss (server clock)"); a paused or refused refresh dims the data and says "showing data from hh:mm:ss". Evidence is shown with its **source**, its **age** against the time the server trusts it, and an exact state: **Verified** (measured by the signed laptop agent, fresh, nothing wrong), **Unhealthy** (the evidence shows a problem), **Stale** (older than the server trusts), **Unknown** (nothing verifiable), **Simulated**, **Unavailable**, plus "Not applicable" lines for signals that do not exist for a kind of device. A browser can only report about itself, so it is never Verified or healthy; a desktop browser is never called a phone (the page sends "Phone/Tablet/Desktop browser" from its user agent and the server keeps only those names); an address on the local machine is shown as "a network change could not be seen", never as "unchanged". The administrator's own session (My session) is under the Account heading, not in a status strip.

**Evaluation mode (demonstration only)** is the one place where a clinical session shows its own risk, device and network evidence and the simulation controls (*My session*, *Demonstration tools*): the page must be opened with `?evaluation=1` **and** the administrator must leave the policy switch `simulation.enabled` ("Evaluation tools enabled") on. It is announced by an "Evaluation mode" pill; the chips say what they refer to and when the server confirmed it ("Desktop browser - Unknown", "Network: Unchanged (local address)", "Session confirmed hh:mm:ss", "Session risk: Low"). A simulated posture or network change is followed by one normal request and the screen shows the server's real decision (Allowed, Step-up required with an *Enter PIN and re-evaluate* button, Denied with the reason) and its effect on session risk. The administrator never gets evaluation mode. When the administrator switches the tools off, the server refuses the simulation requests, stops sending risk figures, limits, posture details and addresses to every role except the security administrator, and an open evaluation page loses its entries at its next session check.

* A session revoked elsewhere (an administrator, the policy) is noticed within the 10 s heartbeat of a browser device (about a minute for the laptop device, via the token renewal) and the screen switches to "Session ended" without any click.
* **Simulated is never presented as measured**: signals carry their source badge; the laptop agent started in demonstration mode is called out; the "Simulated" badge has a dashed outline wherever a value is not a measurement.
* **Nothing sensitive is shown**: no demo credentials, passwords, PINs, tokens or hashes; no personal computer name (the laptop's identifier is derived from it, so every device is shown as "Registered laptop" or "Desktop/Phone/Tablet browser" plus a short fingerprint, and raw identifiers quoted in audit text are replaced the same way); the sign-in screen shows no account, role or patient information.
## 5. Security rules that did not change

Everything is decided on the server on every request: token (device bound) -> session state -> lock / idle / absolute timeout -> endpoint -> role -> device posture -> network -> patient scope (assignment / ward / emergency grant) -> risk -> step-up PIN; the protected app re-checks identity, assignment, ward and grant against the database; every patient-API decision is audited; risk thresholds revoke sessions automatically. Hiding a button is a convenience only: the tests call the API directly for every role (groups B, R, T, X), and the evaluation-mode "Demonstration tools" do the same from the screen. Since 2026-10-13 the server also applies need-to-know to what it sends (risk figures and posture details only to the security administrator, and to others only while the evaluation tools are on) and answers a missing patient number exactly like a patient the caller may not see.

## 6. The one server change: appointment management

The receptionist's job includes moving an appointment, which the old portal could not do. `POST /api/patients/{id}/appointment` with `{"next_appointment":"YYYY-MM-DD HH:MM"}`:

* permitted for the **receptionist only**: a new row in `role_permissions` (the policy engine refuses every other role with `role_denied` before the app is reached), and the protected app checks the account's role again (defence in depth);
* the value is validated by the server (real date and time, in the future, within 12 months, body at most 2 KB) and only the `next_appointment` column is written; the answer carries no clinical field;
* patient scope, risk scoring, step-up and audit apply as for every patient request (sensitivity 20).

Tests: group **T** (through the front door), rows **AP8-AP10** (the protected app on its own), **R18** (permission table), **U6** (through the screen).

## 7. How it was checked

| What | Where |
|---|---|
| all four roles sign in and see exactly their navigation | groups L, R (UI1-UI7) |
| direct API authorization, tampering, path tricks, emergency access | groups B, R, BG, AP, T |
| posture changes, network changes, risk escalation, revocation, lockout (API) | groups C, D, T |
| the same, through the real screens, compared with the audit log | group U |
| 360 px layout, touch targets, drawer, cards | group M |
| installable PWA, service worker, offline page, no protected data in caches | groups A, W |
| Everwell branding: names and tagline, browser titles, install name and home-screen label in the manifest, icons (pixel check), offline page, sign-in and every screen of the four roles at desktop and 360 px, no trace of the old product name | group BR, rows W13, W14, U4 |
| code rules (no HTML insertion, no inline style, storage use) | A17, A18, F11, F12 |

Screenshots of the sign-in screen and every role at desktop and phone size are in `docs/screenshots/` (made by `tests/e2e/run_screenshots.ps1`; the phone images are an emulated 360 px viewport).

**Result of the complete regression after the Everwell Hospital branding** (all groups, run once from a freshly built run folder after the last change): **PASS 217, FAIL 0, NOT RUN 3** (the three NOT RUN rows are P1-P3, the phone). Per group: A 18, W 14, L 9, B 25, C 25, D 23, E 11, F 13, R 18 (+ one NOTE row, R17, an observation), BG 6, AP 10, UI 7, T 10, M 11, U 10, BR 7. The redesign had left the suite at PASS 209 (executed twice, same result); before the redesign it had 174 PASS, the 35 additional rows being the new tests (M, T, U, AP8-AP10, UI7). The branding added 8 rows: BR1-BR7 and W14.

**Result of the complete regression after the role-specific interfaces (2026-10-13)** - all 15 groups in one run on a freshly set-up, built and started run folder (`demo.ps1` setup, build, start all exit 0): **PASS 249, FAIL 0, NOT RUN 3** (775 s; the three NOT RUN rows are P1-P3, the phone). Per group: A 18, W 14, L 9, B 25, C 25, D 23, E 11, F 13, R 19, BG 6, AP 10, UI 7, T 10, M 11, U 10, BR 7, X 15, RU 16. How it got there (nothing hidden; the failure logs are kept unchanged in the evidence folder):
* First complete run: PASS 221, FAIL 3, NOT RUN 3. U2 failed (after the PIN the chip still said "Changed (simulated)": a simulated address was not recognised as unchanged; fixed in `networkEvidence`). M0 and RU0 failed because the browser scripts stalled for about 14 minutes each (a DevTools command was never answered; the stack itself answered in milliseconds); only those two script processes and their throw-away Chrome profiles were stopped. Root cause of the stall: **not established**; mitigation: every DevTools command now has a 60 s limit and every fetch 30 s, so a stall fails loudly instead of hanging. The later runs (M alone 139 s, the whole suite 775 s) did not stall.
* Standalone M run: PASS 7, FAIL 4. M3, M4, M5 and M11 were a real defect: in evaluation mode the top bar (title, pill, chips, account button on one line) overflowed a 360 px phone and a 1024 px window. Fixed in `styles.css` (the evaluation chips wrap on their own row under the title); M1-M11 then passed.
* Re-run of M, U and RU after the fixes: PASS 35, FAIL 2, NOT RUN 3. RU8 and RU9 found no device card on the administrator's Devices screen once. **Cause not established and not reproduced**: the same screen rendered all 191 device cards in under 750 ms in a separate headless Chrome, every admin endpoint answered within 75 ms, RU alone then passed (16 of 16) and so did the complete run. The two rows now print the page state if it happens again. This is an intermittent failure that was observed once; it is not claimed to be fixed.
* The first interim run, taken right after the server change that removed the patient-existence oracle, failed 39 rows (a cascade: B10-B12 together added 60 risk points, which revoked and locked the doctor's session). The test was corrected so B12 uses its own session; X proves the oracle fix (X4-X6) and all of them passed afterwards.

Mutation checks of the new tests (each was made to fail on purpose and then restored, file hashes compared): UI7 fails when the device-identifier replacement is switched off (the administrator screens then show the computer-derived laptop identifier); AP8 fails when the protected app's role check for appointments is removed (a nurse's claims then change an appointment); M2 and M7 fail with 30 px buttons (79 small touch targets found); U1 and U2 fail when the screen shows the wrong decision for a step-up.

Mutation checks of the branding tests (same method: change on purpose, expect FAIL, restore, compare hashes, run again): with the old product name put back into the offline page, the manifest and the app's sidebar and titles, and the teal ring erased from the 512 px icon, BR1, BR2, BR3, BR5 and BR7 failed (BR4 and BR6 were not affected by that change and stayed PASS); with only the sign-in card's portal name replaced by "Hospital Portal", BR4 alone failed (page text lacks "Everwell Health Portal" at 1280 and 360 px) and the other BR rows passed. After each restore the file hashes equalled the originals and the BR group passed again (7 PASS). BR6 (the hospital name returned by the back end) has no mutation proof of its own: changing it means recompiling and restarting the protected app, which was not done for a data string; BR1 checks the same string in the source file.

## 8. Remaining limitations

* **No real phone was used.** Installation (P1), the offline page on the phone (P2) and a live scenario on the phone (P3) are NOT RUN; the 360 px results are emulation in desktop Chrome.
* **Branding on a device is unverified.** The home-screen name ("Everwell") and icon were checked from the manifest as Chrome parses it, the served files and the icon pixels, not on a phone. Chrome refreshes an installed app's name and icon from the manifest on its own schedule (not immediately; an older home-screen shortcut may have to be removed and added again). This was not observed because no phone was used.
* The demo certificate authority and the server certificate keep their original subject names ("ZT Demo Root CA", "ZT Hospital Portal (academic demo)"): renaming them means issuing new certificates and changing what a device trusts, which is outside a branding change. A certificate viewer therefore still shows those names, and the scripts and tests that create or check them keep the older wording.
* "Everwell Hospital" is a fictional name chosen for the demonstration; it was not checked against real organisations or trademarks.
* Screen-reader behaviour was not tested with an actual screen reader; the markup follows the usual patterns (landmarks, headings, labels, `aria-current`, native dialogs, live regions for alerts and toasts) and the drawer behaviour is tested, but that is not an accessibility audit.
* Dates and times use the browser's locale for display; the appointment API itself is fixed to `YYYY-MM-DD HH:MM` in the server's local time.
* Appointment management is limited to moving the next appointment (no new appointment, no cancellation, no history).
* The export dialog shows synthetic identifiers masked by default; the endpoint itself still returns them by design (earlier finding, unchanged).
* The administrator's live views poll every 6-8 s and pause on the first refusal; they are not push-based.
* Nothing here is production-ready: the earlier limits (PBKDF2 instead of Argon2id, loopback-only internal TLS without validation, tests are samples) still apply.
