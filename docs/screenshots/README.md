# Screenshots of the Everwell Health Portal (2026-10-12, after the Everwell Hospital branding)

> **NOT refreshed after the role-based dashboard correction of 2026-10-13 (`docs\ROLE_UX_AUDIT.md`).** These images show the interface as it was on 2026-10-12.
> Since then the clinical workspaces (doctor, nurse, receptionist) no longer show the top-bar status chips, the "Session & access" screen or the
> "Demonstration tools" screen unless evaluation mode is on (`/?evaluation=1`, and only while the security administrator allows it); they have an
> account menu (avatar) instead, and the security console has no chips. So `doctor-session-*`, `doctor-demo-*` and the chip strip visible in the
> other clinical images describe the former behaviour, not the current one. `tests\e2e\run_screenshots.ps1` was updated for the new screens
> (account menu, `evaluation-doctor-*`) but **was not run** after the correction: regenerate the set with it before using these images as evidence.

Taken from the **running** portal (real servers, synthetic patient data) by `tests\e2e\run_screenshots.ps1` in headless desktop Chrome with a
throw-away profile. Desktop images are 1440 x 900 CSS pixels. **Phone images are an emulated viewport of 360 x 740 CSS pixels (device pixel
ratio 2, touch and mobile emulation) in desktop Chrome; they show the phone layout but were NOT taken on a real phone.** No credential, token or
PIN appears in any image (the sign-in fields are empty; the script types them without printing them).

| Screen | Desktop | Phone (emulated 360 px) |
|---|---|---|
| Sign-in | `login-desktop.png` | `login-phone.png` |
| **Doctor** dashboard: assigned patients, chart (diagnosis, medication, care notes, export) | `doctor-dashboard-desktop.png` | `doctor-dashboard-phone.png` (list), `doctor-patient-chart-phone.png` (chart) |
| Doctor: patient not assigned, emergency access offered | `doctor-access-restricted-desktop.png` | `doctor-access-restricted-phone.png` |
| Doctor: emergency access dialog; granted access (read-only banner, countdown) | `doctor-emergency-dialog-desktop.png`, `doctor-emergency-access-desktop.png` | `doctor-emergency-dialog-phone.png`, `doctor-emergency-access-phone.png` |
| Doctor: session and device posture (Measured / Self-reported / Simulated) | `doctor-session-desktop.png` | `doctor-session-phone.png` |
| Doctor: demonstration tools; simulated posture change and the real decision; simulated network change | `doctor-demo-tools-desktop.png`, `doctor-demo-posture-change-desktop.png`, `doctor-demo-network-change-desktop.png` | `doctor-demo-tools-phone.png`, `doctor-demo-posture-change-phone.png`, `doctor-demo-network-change-phone.png` |
| **Nurse** dashboard: ward patients, medication and care notes only | `nurse-dashboard-desktop.png` | `nurse-dashboard-phone.png`, `nurse-patient-chart-phone.png` |
| Nurse: patient of another ward refused | `nurse-other-ward-refused-desktop.png` | `nurse-other-ward-refused-phone.png` |
| **Receptionist** dashboard: patient registry, demographics, appointment | `receptionist-dashboard-desktop.png` | `receptionist-dashboard-phone.png`, `receptionist-patient-phone.png` |
| Receptionist: appointments, reschedule dialog | `receptionist-appointments-desktop.png`, `receptionist-reschedule-dialog-desktop.png` | `receptionist-appointments-phone.png`, `receptionist-reschedule-dialog-phone.png` |
| **Security administrator** dashboard: counters, risk alerts, security events | `admin-overview-desktop.png` | `admin-overview-phone.png` |
| Administrator: sessions, devices and posture, access decisions, audit log, users and emergency access, policy, own session | `admin-sessions-desktop.png`, `admin-devices-desktop.png`, `admin-decisions-desktop.png`, `admin-audit-desktop.png`, `admin-users-desktop.png`, `admin-policy-desktop.png`, `admin-session-desktop.png` | the same names with `-phone` |

The sessions screen shows only the administrator's own session in these images because the images were taken right after a clean start (the
screens list real sessions; nothing is staged). The numbers on the overview screens come from the sign-ins, denials and the emergency access
made by the screenshot script itself.
