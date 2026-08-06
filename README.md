# VibeCheck

Scans any public web app for exposed LLM API keys, open API endpoints,
and CORS misconfigurations — using only what a visitor's browser
already receives.

## What it checks

- LLM API keys in HTML and linked JS bundles (OpenAI, Anthropic, Gemini,
  Groq, xAI, Fireworks, Replicate, and 15+ more)
- API endpoints in JS that respond without authentication
- Wildcard or credential-bearing CORS headers
- Every finding includes a concrete fix recommendation

## Local setup

```bash
git clone https://github.com/yourname/vibecheck
cd vibecheck
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

Open http://localhost:8000

## Environment variables

| Variable               | Required in prod | Description |
|------------------------|-----------------|-------------|
| `SECRET_KEY`           | Yes             | Long random string. Never commit this. |
| `DEBUG`                | Yes             | Set to `False` in production. |
| `ALLOWED_HOSTS`        | Yes             | Space-separated list of allowed hostnames. |
| `CSRF_TRUSTED_ORIGINS` | Yes             | Space-separated list of trusted origins (e.g. `https://yourdomain.com`). |
| `PGHOST`               | No              | Set to enable Postgres. Leave unset to use SQLite. |
| `PGDATABASE`           | No              | Postgres database name. Default: `vibecheck`. |
| `PGUSER`               | No              | Postgres user. Default: `postgres`. |
| `PGPASSWORD`           | No              | Postgres password. |
| `PGPORT`               | No              | Postgres port. Default: `5432`. |
| `REDIS_URL`            | Recommended     | Redis URL. Without this, rate limiting is per-process — broken with multiple gunicorn workers. |
| `SENTRY_DSN`           | No              | Sentry DSN for error monitoring. |

## Running tests

```bash
python manage.py test scanner --verbosity=2
```

36 tests covering SSRF protection, pattern matching, scanner service,
views, middleware, and the cleanup management command.

## Verify deployment config

```bash
# Windows PowerShell
$env:DEBUG="False"
$env:SECRET_KEY="abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop"
$env:ALLOWED_HOSTS="localhost"
python manage.py check --deploy
# Should print: System check identified no issues.

# Reset for local dev
$env:DEBUG="True"; $env:SECRET_KEY=""; $env:ALLOWED_HOSTS=""
```

## Deploy (Render / Railway / Heroku)

```bash
python manage.py collectstatic --no-input
```

The `Procfile` runs migrations automatically on every deploy: