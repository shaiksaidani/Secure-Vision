# Deploying SecureVision

Work through this list in order. Do not skip the backup section: without the
file encryption key, protected files and evidence cannot be recovered.

## 0. Platform note (read first)

SecureVision was built and tested on **Python 3.6.8 with Django 3.2**. Both
are past end-of-life (Python 3.6 since December 2021, Django 3.2 since April
2024) and no longer receive security fixes. That is fine for a project
demonstration on your own machine. For real users, move to a supported
Python (3.12) and Django LTS release first; the code avoids version-specific
features, but run the full test suite after upgrading.

## 1. Before you deploy

```powershell
python manage.py test                 # every test must pass
python manage.py check --deploy       # with your production .env in place
```

`check --deploy` lists Django's warnings plus SecureVision's own checks
(`securevision.E001` ... `W004`). Fix every **Error**; read every **Warning**.

## 2. Production `.env`

Generate secrets (run each once and paste the output into `.env`):

```powershell
python -c "import secrets; print(secrets.token_urlsafe(50))"          # SV_SECRET_KEY
python -c "import secrets; print(secrets.token_urlsafe(18))"          # each sign-up code
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"   # SV_FILE_ENCRYPTION_KEY
```

| Setting | Production value |
|---|---|
| `SV_DEBUG` | `False` |
| `SV_SECRET_KEY` | the generated value |
| `SV_ALLOWED_HOSTS` | your host name, e.g. `securevision.example.com` |
| `SV_FILE_ENCRYPTION_KEY` | the generated Fernet key (see section 5 before changing it) |
| `SV_TEAM_LEADER_SIGNUP_CODE`, `SV_ADMIN_SIGNUP_CODE` | new random values, or empty to disable self sign-up for that role |
| `SV_REVEAL_UNKNOWN_EMAIL` | `False` |
| `SV_SECURE_COOKIES` | `True` |
| `SV_EMAIL_BACKEND` and `SV_EMAIL_*` | your SMTP server, so password-reset emails are delivered |
| `SV_DB_ENGINE` | `postgresql` for several concurrent users (`pip install psycopg2-binary==2.8.6`) |

**Moving an existing database to a new encryption key:** files already stored
were encrypted with the old key (`.dev_file_key` in development). Either start
with a fresh `protected_storage` folder and database, or set
`SV_FILE_ENCRYPTION_KEY` to the contents of `.dev_file_key` and back it up.

## 3. Install, migrate, collect static files

```powershell
pip install -r requirements.txt
pip install waitress==2.0.0 whitenoise==5.3.0
python manage.py migrate
python manage.py collectstatic
python manage.py createsuperuser
```

Set `SV_SERVE_STATIC=True` if no separate web server will serve `/static/`.

## 4. Run behind HTTPS

Run the app server on the local machine only:

```powershell
waitress-serve --listen=127.0.0.1:8000 securevision.wsgi:application
```

Put a reverse proxy in front for HTTPS. With Caddy (automatic certificates),
a `Caddyfile` is one block:

```
securevision.example.com {
    reverse_proxy 127.0.0.1:8000
}
```

Then, in `.env`:

```
SV_BEHIND_HTTPS_PROXY=True
SV_TRUST_X_FORWARDED_FOR=True
SV_SSL_REDIRECT=True
SV_CSRF_TRUSTED_ORIGINS=https://securevision.example.com
SV_HSTS_SECONDS=3600
```

Raise `SV_HSTS_SECONDS` to `31536000` (one year) only after you have confirmed
HTTPS works everywhere: browsers will then refuse plain HTTP for that long.

## 5. Backups (essential)

Back up **all three** together, regularly, and test a restore:

1. The database (`db.sqlite3`, or a PostgreSQL dump).
2. The `protected_storage` folder (encrypted files, forensic samples, evidence).
3. The file encryption key (`SV_FILE_ENCRYPTION_KEY`), stored **separately**
   from the other two, for example in a password manager.

Losing the key makes every protected file and evidence item unreadable.
Leaking the key together with a storage backup exposes them.

## 6. Running it

* Review the **Security Center** daily; open an incident for anything real.
* Change the sign-up codes whenever someone who knew them leaves.
* Review **Devices** and **User Management** when people leave: deactivate the account and remove its devices.
* Export **Activity Logs** for your records on a schedule that suits your policy.

## 7. Known limitations (be honest about them)

* No two-factor authentication yet; strong passwords and the lockout are the defence.
* Invisible watermarks are for images and survive copying and cropping, not
  JPEG re-compression, resizing or screenshots. PDFs and documents are traced
  by exact hash and access records only.
* Uploaded files are type-checked but not virus-scanned.
* One file encryption key with no automatic rotation.
* Chat updates by polling every 4 seconds rather than a live connection.
* Visible watermarks and "view only" deter casual copying; nothing can stop a
  determined person from photographing a screen. The forensic trail is what
  makes leaks traceable.