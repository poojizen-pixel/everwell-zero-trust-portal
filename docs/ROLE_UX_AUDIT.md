# Role-based dashboards and Zero Trust UX: audit and correction (2026-10-13)

Academic demonstration, **synthetic patient data only**. This note records what was found when every role, route, navigation item, shared
component, status indicator, button, API endpoint, authorization check and test of the Everwell Health Portal was inspected (state: checkpoint D9,
the verified Everwell branding), what was changed, and what was verified by executed tests. It does not claim production readiness.

Rollback: checkpoint **D10** (`C:\Ap_project_checkpoints\...-D10-before-role-ux-correction`, plus a plain copy of `web\`, `tests\e2e\`, `docs\` and
`db\schema_demo.sql`) was saved before the first change; D9 and the original backup are untouched.

## 1. Does the security administrator perform the SOC function?

Yes, and that permission model was kept unchanged. The role `security_admin` is permitted exactly the administration endpoints (`/admin/summary`,
`sessions`, `sessions/revoke`, `devices`, `events`, `policy`, `policy/set`, `grants`, `grants/revoke`, `users`, `unlock`), `/ctl/policy` (the full
policy) and its own session functions. It has **no** patient endpoint (list, summary, records, export, appointment, emergency access): the role gate
refuses them before any scoring, and the protected application refuses them again. The security console (overview, sessions, devices, decisions,
audit log, users and emergency grants, policy, own session) is the SOC. Monitoring does not imply clinical access, and no new permission was added to
any role.

## 2. Audit of the state at D9

### 2.1 What was shared across roles

| Component | Shared how |
|---|---|
| One application shell (`mountShell`) | sidebar, top bar, banner stack and page for all four roles |
| **Status chips in the top bar** | "Session active", "Network unchanged", "<device> - Healthy", "Risk: Low": built for every role, the administrator included |
| `Session & access` screen | the same code showed every clinical role (and the administrator, as "My session") the risk meter in points, the device signal list, the sign-in and evaluated network addresses, the scoring rules and a request log |
| `Demonstration tools` screen | a navigation item of the three clinical roles: server probes for any patient number, "Send 5 restricted requests", simulated network and posture switches, a decision log |
| Denial explanations, PIN dialog, end-of-session screen | for every role: the server's own wording, reference codes, "Technical detail" disclosures, risk points and limits |
| Patient workspace | one view for doctor, nurse and receptionist (role switches inside) |

### 2.2 Security indicators each role saw

| Role | Indicators |
|---|---|
| Doctor, nurse, receptionist | four top-bar chips on every screen; the session risk, posture and network screen; the demonstration screen with a risk meter and a decision log; denial messages with technical detail (server text with the risk score and limits, codes); a PIN dialog with the policy reason; an end-of-session screen with the decision, the risk points and a reference code |
| Security administrator | the same four chips about **the administrator's own** session and device, next to a console that lists other users' risk alerts (see 2.5); the eight console screens |

### 2.3 Screens that exposed unnecessary technical or security information

* `Session & access` (clinical roles): risk points and limit, device signals with their sources, the user's own IP addresses, the scoring rules and thresholds.
* `Demonstration tools` (clinical roles): policy decisions, a risk meter, simulated posture and network controls.
* Every denial, PIN and end-of-session message of a clinical user: server wording that quotes risk scores, limits, network addresses, heartbeat ages and lock reasons.
* API: every denial body and `/ctl/session` returned the session risk, the revoke limit, the scoring breakdown, the device posture signals and the network addresses to every role, whatever the page showed.

### 2.4 Buttons and actions that exceeded a role's needs or contradicted its permissions

* **Security administrator, "My session" > "Check access now"** requested `GET /api/patients/list`, which that role may never call: every click was refused by design (`role_denied`) and added 15 points to the administrator's own session risk; four clicks revoked the administrator's session and locked the account.
* Clinical roles: "Send 5 restricted requests" (drove the user's own session to revocation and lockout), the receptionist's "Run access-control test" (requests a clinical record on purpose), "Apply and re-evaluate" and "Reset simulated signals" (change what the server evaluates for the session): demonstration aids sitting in the clinical navigation.
* `POST /ctl/simulate` is in every role's permission set and enabled by default: any signed-in user could change the address the server evaluates for their own session (including masking a real network change by simulating the sign-in address) and the three simulated posture signals of a browser device.

### 2.5 Displayed states that were unsupported, stale, ambiguous or misleading

| State | Problem |
|---|---|
| "Session active" | constant text, tied to no check |
| "Network unchanged" | no time of check; unprovable for a local address (on one machine, or over a USB route, the server cannot see the real network); simulated addresses looked like real ones |
| "This phone/browser - Healthy" | called every browser a phone (a desktop Chrome included); "healthy" meant only "no negative self-reported or simulated signal and a recent heartbeat": nothing is measured for a browser, three of its signals are simulated defaults, and unknown signals did not lower it |
| "Risk: Low" in the administrator's top bar | the administrator's **own** session, next to a console that lists other users' alerts: reads as system status |
| device names "Phone/browser <id>" | ambiguous in the administrator's tables; the old text scrubber also named desktop identifiers "Phone/browser" |
| paused or refused live data | a refused refresh left the last numbers on screen with only a small "Paused": old values looked current |
| appointment dates ("today", "in 2 days") | computed with the browser's clock instead of the server's |
| patient numbers | a missing number (404) differed from an unassigned or other-ward patient (403) for a doctor or nurse: a patient-existence oracle; `/ctl/break-glass` answered 404 for a missing patient before it checked the justification |

### 2.6 Backend endpoints that needed more authorization tests

The existing groups B, R, T, BG, AP and E covered the patient endpoints, the administration endpoints for the clinical roles, break-glass and the
appointment endpoint. Gaps found: no table-driven test of **every** endpoint for **every** role (including `/ctl/simulate`, `/ctl/policy`, heartbeat,
renewal and sign-out), no check that refused requests change nothing, no unauthenticated sweep, no check of what a refusal reveals (patient
existence, risk figures, addresses), no test of the evaluation switch on the server, none of the device label a client may choose, and no browser
test that a clinical page never calls an administration endpoint. Groups **X** and **RU** were added (section 5).

## 3. The corrected design

### 3.1 Principles

1. **The server decides, always.** Hiding a screen or disabling a button is a convenience, never a control: every request is still authenticated, authorized, scoped, risk-scored and audited on the server, and every new test calls the API directly as well.
2. **A clinical workspace shows clinical work.** Security information appears to a clinical user only when it needs them to act (a step-up PIN, a refusal, a session that is about to end or has ended), in plain words, never as a dashboard.
3. **Security monitoring lives in the security console**, with the time, the source and the age of every piece of evidence, and an exact vocabulary for what the evidence supports. An unknown state is never shown as healthy.
4. **Need-to-know on the wire too**: risk figures, limits, posture details and network addresses are sent to non-administrators only while the administrator allows evaluation.

### 3.2 Role by role

| Role | Navigation | What the workspace contains |
|---|---|---|
| Doctor | My patients | assigned patients (search, open by number), **Next visits**, patient banner, diagnosis, medication, care notes, clinical summary export (assigned patients, step-up PIN, identifiers masked on screen); a patient outside the list shows one plain refusal (the same for a missing number) and the emergency-access request (justification, confirmation, read-only, time-limited, this sign-in only); the account menu |
| Nurse | Ward patients | ward patients, **Next visits**, medication and care notes only (no diagnosis, no export, no emergency access); another ward's patient (or a missing number) shows one plain refusal; the account menu |
| Receptionist | Patient registry, Appointments | demographics and appointments only, reschedule (the one write); no clinical wording, no emergency or export control; the account menu. (Registering a new patient is **not** implemented in this build: it would be a new write permission, outside a UX correction.) |
| Security administrator (SOC) | Overview, Sessions, Devices & posture, Access decisions, Audit log, Users & access, Policy, My session | monitoring and administration, never patient data (section 3.4) |

Every clinical workspace has only the top bar's **account button** (avatar): name, role (and ward), sign-in time, the automatic sign-out and the
longest session, the server's confirmation of the session, Sign out. Two plain notices exist because they ask for action: "You will be signed out
soon" (with "Stay signed in", which really counts as activity) and "Maximum session length". The end-of-session screen says what happened in plain
words (revoked: "Your session was ended for security reasons"; expired: after a period without activity, or the maximum length; locked: until a time).

### 3.3 Indicators removed, retained or relocated

| Indicator | Decision | Reason |
|---|---|---|
| Top-bar chips (session, network, device, risk) for doctor, nurse, receptionist | removed from the workspace; **relocated** to evaluation mode only | decorative for clinical work; two of them claimed more than the evidence supports |
| The same chips for the security administrator | removed | they described the administrator's own session next to system-wide data |
| `Session & access` and `Demonstration tools` of clinical roles | relocated to **evaluation mode** (off by default) | demonstration aids, not clinical work |
| Technical detail, reference codes, risk points in a clinical user's messages | removed; plain words | a clinician needs to know what to do, not a score |
| Step-up dialog, refusals, session ended, emergency banner and countdown | retained, in plain words | they ask the user to act |
| Session expiry and longest-session notices, account menu | **added** | minimal, actionable session feedback from the server's own limits |
| SOC screens | retained and improved (3.4) | primary place for monitoring |

### 3.4 Security console (SOC)

No chips; the console says what it shows. Every live screen states when its data was read ("Live - updated hh:mm:ss (server clock)"); when the
refresh is paused or refused, the data is dimmed and labelled "showing data from hh:mm:ss". **Sessions**: per row the device (label, short
fingerprint, evidence state), the network evidence (address at sign-in with its time, the address at the latest recorded event, "unchanged" only
when the evidence supports it, "local address: a network change could not be seen" otherwise), the risk in points against the limit, the last
activity with its age. **Devices & posture**: every device with an exact state, why, the evidence source, the age of the last report against the
time the server trusts a report, who is signed in on it and the signals that do not apply to that kind of device. **Access decisions**: a "Network
changes" filter and "Contributing signals". **Policy**: "Evaluation tools enabled" explains what the switch does.

Evidence vocabulary (the page derives it from the server's data; it adds no evidence): **Verified** (measured by the signed laptop agent, fresh,
nothing wrong), **Unhealthy** (the evidence shows a problem, with the reason), **Stale** (the last report is older than the server trusts), **Unknown**
(nothing verifiable: a browser can only report about itself), **Simulated** (a demonstration value), **Unavailable** (no record), and "Not
applicable" lines for signals that do not exist for that kind. A browser is never Verified or healthy; a desktop browser is never a phone (the
sign-in screen says "This browser"; the page sends "Phone/Tablet/Desktop browser" from its user agent, and the **server** keeps only those three
names, so a client cannot call itself "Registered laptop").

### 3.5 Evaluation mode

The one place where a clinical session shows its own risk, device and network evidence and offers the simulation controls (it exists so the
academic demonstration can show those decisions). It is **off** unless the page is opened with `?evaluation=1` **and** the security administrator
leaves the policy switch `simulation.enabled` ("Evaluation tools enabled") on. It adds the navigation group "Evaluation mode (demonstration only)"
(My session, Demonstration tools), an "Evaluation mode" pill and the chips, which name what they refer to and when the server confirmed it ("Desktop
browser - Unknown", "Network: Unchanged (local address)", "Session confirmed hh:mm:ss"). The administrator never gets it. Switching the tools off
removes it from an open page at its next session check; the server then refuses `/ctl/simulate`, sends **no** risk figures, limits, posture details
or addresses to any role except the security administrator, and uses plain refusal messages.

## 4. Backend changes (and why)

| Change | File | Why |
|---|---|---|
| A missing patient number is answered exactly like a patient the caller may not see (doctor: `not_assigned`, nurse: `ward_denied`; same status, text, session-risk penalty and audit record); only the front desk, which works with the whole directory, still gets `not_found` | `ScopeService`, protected app `Access` | no patient-existence oracle |
| Emergency access checks the justification **before** the patient number; a missing number then costs the same session risk as an unassigned one | `GatewayHandler.breakGlass` | the request could be used to probe numbers without a justification |
| Need-to-know: `Decision.detail`; while the evaluation tools are off, refusal bodies carry no risk figure, limit or scoring detail and say plain words (no quoted address, heartbeat age or lock reason); `/ctl/session` returns only identity, session limits, the server clock and (doctors) the emergency-access rules; the lock message at sign-in drops the reason | `Decision`, `Decider`, `GatewayHandler` | the page hid these; the API still sent them |
| `/ctl/session` always reports `idle_timeout_seconds`, `absolute_expires_at`, `server_time`, and `detail` (full / limited); the device block adds `heartbeat_age` and `stale_after_seconds` | `GatewayHandler` | session notices from the server's own limits, authoritative dates, evidence freshness |
| `/admin/sessions` adds `evidence_ip` / `evidence_ts` (address and time of the latest recorded event) and `server_time`; `/admin/devices` adds `stale_after_seconds` and `server_time` | `SessionService`, `GatewayHandler` | evidence age and source in the console; nothing is fabricated: the server records no address for unaudited polling |
| Device labels are canonical (Phone / Tablet / Desktop browser, else Browser) | `GatewayHandler.login` | a client must not choose a misleading device name |

Nothing in token, session, role, scope, posture, network or risk **enforcement** was weakened; the audit log still receives the full detail.

## 5. Tests added or changed

* **X** (new, 15 rows): the endpoint x role matrix (23 endpoints x 4 roles = 92 calls) with the table written independently of the database; refused requests change nothing; every endpoint without a token answers 401; no existence oracle (doctor, nurse), the emergency-access order, the front-desk exception; device labels; need-to-know ON and OFF (refusals, session view, revocation and lockout, stale device, network change); the simulation switch; sign-out.
* **RU** (new, 15 rows, real Chrome): the three clinical workspaces in every state have no security monitoring, chips or foreign controls and make no administration request; plain language for a refusal and the step-up dialog; the console keeps its monitoring with evidence and times; routes of other roles lead nowhere; device labels (desktop, phone and tablet user agents); unknown and stale evidence is never healthy; honest network evidence; evaluation mode on request and off on policy; the administrator's screens carry no patient data and its direct calls are refused; the account menu; the session notices; the end-of-session screens.
* Changed because the interface changed: B12, R17 (the oracle), UI1, UI2, UI5, W7, L2, L6, L7, M3-M6, M10, M11, U1-U5, U8, BR5.

## 6. Results, evidence and limitations

* **Complete regression** (all 15 groups, one run, freshly set-up, built and started run folder): **PASS 249, FAIL 0, NOT RUN 3**. The three NOT RUN rows (P1-P3: install, offline page and a live scenario on the phone) can only be run on a physical phone. The history of the earlier failures (U2, M3-M5, M11, two script stalls, one intermittent RU8/RU9) and their fixes is in `docs/UI_DESIGN.md` section 7; the unchanged failure logs are in `C:\Ap_project_evidence\DEMO\...-failures-before-blocker-fix`.
* **Found and fixed on 2026-10-13, after the audit above:** the evaluation-mode top bar overflowed a 360 px phone and a 1024 px window (the chips now sit on their own row); a simulated address was shown as "Changed (simulated)" after the step-up (it is now "Unchanged (simulated address)").
* **Checkpoints:** D10 (before this correction) and **D11** (the finished, regression-verified state; the folder is named `...-D11-role-ux-phone-ready` under `C:\Ap_project_checkpoints`, evidence under `C:\Ap_project_evidence\DEMO`). D9 and the original backup are unchanged.
* **Not done / not established:** mutation proofs for the new X and RU rows (NOT RUN); the screenshots in `docs/screenshots` were not regenerated (see its README); a physical phone was not used (P1-P3); a screen reader was not used; one intermittent RU8/RU9 failure and two browser-script stalls have no established root cause (time limits and page-state diagnostics were added; later runs passed). The role matrix in `docs/ROLE_REVIEW.md` section 4 was regenerated from the final run.
* **System settings:** no firewall rule, network setting, certificate-trust setting or other operating-system security setting was created or changed (verified again at D11: no firewall rule named ZT*, the Windows root store unchanged, the demo CA in no Windows store).
