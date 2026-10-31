# SecureVision

An enterprise security workspace built with Django: protected file sharing with
encryption, watermarking and forensic tracing, confidential chat, attendance,
device control, a Security Center, incident management with an evidence vault,
and a complete, append-only audit trail.

## Modules

| Module | What it does |
|---|---|
| Accounts | Email sign-in, roles (Employee, Team Leader, Admin), sign-up role codes, sessions you can end remotely, password reset, sign-in lockout |
| Devices | Each browser registers as a device; per-account device limit; removing a device signs it out |
| Teams | Teams with leaders and members; everything else is scoped by team |
| DRM Hub / Stored Data | Files encrypted at rest (Fernet), SHA-256 integrity checks, magic-byte type checks, team or person grants, expiry, view-only or download, visible watermark |
| Forensic watermarking | Every person gets a uniquely, invisibly marked copy of protected images |
| Forensic Analyzer | Upload a suspicious file: exact-match, watermark and visual-similarity checks, the recipient it traces to, access history and a risk rating |
| Access Requests | Employees request restricted files; admins approve (grants access) or reject |
| Confidential Chat | Direct messages and team communities, announcements, soft delete, live updates |
| Attendance | Check in / out, late detection, leave and absence, team views, daily/weekly/monthly reports |
| Notifications | Per-person bell: access granted, expiring files, announcements, requests, security alerts |
| Security Center | Alerts raised automatically from the audit log (repeated denials, lockouts, integrity failures, traced leaks, download bursts...) |
| Incidents and Evidence Vault | Incidents with an append-only timeline; encrypted, hashed, append-only evidence with a chain of custody; printable reports |
| Activity Logs and Reports | Searchable audit timeline, security summary and file-access reports, CSV exports (all audited) |

## Requirements

* Windows, Python **3.6.8** (see "Platform note" in DEPLOYMENT.md), PowerShell
* Packages in `requirements.txt` (Django 3.2, cryptography 40, Pillow 8.4)

## Run it locally

```powershell
cd "C:\Users\shaik\OneDrive\Desktop\secure vision"
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade "pip<22"
pip install -r requirements.txt
Copy-Item .env.example .env        # then set the two sign-up codes
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

Open http://127.0.0.1:8000. Every terminal needs `(venv)` active first.

## Tests

```powershell
python manage.py test
```

163 automated tests cover sign-in, roles, sessions, devices, teams, file
protection, watermarking, forensics, chat, attendance, notifications, alerts,
lockout, incidents, evidence integrity, reports and security headers.

## Security design (short version)

* Identity always comes from the server-side session and the database, never from the browser.
* Every page and action checks a named privilege on the server; hidden buttons are not security.
* Protected files and evidence are encrypted at rest and verified by SHA-256 on every read.
* The audit log, incident timelines, evidence and custody records are append-only.
* Content-Security-Policy, X-Frame-Options, nosniff, Permissions-Policy, no-store on signed-in pages.
* `python manage.py check --deploy` runs SecureVision's own deployment checks as well as Django's.

See **DEPLOYMENT.md** before putting SecureVision in front of real users.