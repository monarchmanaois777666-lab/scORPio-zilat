# Member access gateway

This separate FastAPI service serves the public landing page and gates the app itself. It does not import or proxy the trading server. Do not publish `docs/` separately through GitHub Pages or another static host, because a static copy bypasses server-side account checks.

## Access flow

- A member signs up with their email and a password of at least 12 characters.
- The service emails a random, single-use activation code to the configured owner email. The member asks the owner to share it.
- Redeeming the code activates app access for 30 days. The member keeps using their own login password.
- After expiry, the member signs in, requests renewal, and contacts the owner for the new one-time code. The service emails that code to the owner.
- Codes expire after 24 hours. Passwords and codes are stored as hashes; member sessions use an HTTP-only, same-site cookie.

## Run locally

Python 3.11 or newer is recommended.

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r member_auth/requirements.txt
export MEMBER_OWNER_EMAIL="owner@example.com"
export MEMBER_SMTP_HOST="smtp.example.com"
export MEMBER_SMTP_PORT="587"
export MEMBER_SMTP_USERNAME="smtp-user"
export MEMBER_SMTP_PASSWORD="set-this-in-your-host's-secret settings"
export MEMBER_SMTP_FROM="owner@example.com"
export COOKIE_SECURE=0
uvicorn member_auth.app:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`. `COOKIE_SECURE=0` is only for local HTTP testing. Use HTTPS and leave it enabled in production. Do not commit mail credentials or the SQLite database.

## Run in Docker

```sh
docker build -t scorpio-member-app .
docker run --rm -p 8000:8000 -e COOKIE_SECURE=0 -v scorpio-member-data:/data scorpio-member-app
```

The Docker preview serves the public landing and account screen. Sign-up and code delivery require the SMTP environment variables below; without them, registration is intentionally unavailable.

## Production configuration

Set `MEMBER_OWNER_EMAIL`, `MEMBER_SMTP_HOST`, `MEMBER_SMTP_PORT`, `MEMBER_SMTP_USERNAME`, `MEMBER_SMTP_PASSWORD`, and `MEMBER_SMTP_FROM` as host environment secrets. Set `MEMBER_DB_PATH` to persistent storage and `PUBLIC_BASE_URL` to the canonical HTTPS site URL. Run behind a managed HTTPS reverse proxy and keep `COOKIE_SECURE=1`. Back up the database securely.

The public landing page is available at `/`; only it is intended for search indexing. The account page is `/account`; the protected app is `/app`. After deploying to a public domain, verify the domain in Google Search Console and submit `https://your-domain/sitemap.xml`. Search indexing is controlled by Google and is not immediate.

The current service has no owner dashboard, password-reset email, or trading integration. A member access code only grants the app's member experience; never give members the trading server's owner token.