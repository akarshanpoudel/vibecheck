import json
import logging
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# ---- Sentry (initialised before everything else) ----------------------
import sentry_sdk

_sentry_dsn = os.environ.get("SENTRY_DSN")
if _sentry_dsn:
    sentry_sdk.init(
        dsn=_sentry_dsn,
        traces_sample_rate=0.1,    # 10 % of transactions for perf monitoring
        profiles_sample_rate=0.0,  # disable profiling
        send_default_pii=False,    # never send IPs or usernames
        environment="production" if os.environ.get("DEBUG", "True") != "True" else "development",
    )

# ---- Core -------------------------------------------------------------
SECRET_KEY = os.environ.get(
    "SECRET_KEY",
    "dev-only-insecure-key-replace-before-deploying",
)

DEBUG = os.environ.get("DEBUG", "True") == "True"

ALLOWED_HOSTS = os.environ.get(
    "ALLOWED_HOSTS",
    "localhost 127.0.0.1 [::1]",
).split()

CSRF_TRUSTED_ORIGINS = [
    o for o in os.environ.get("CSRF_TRUSTED_ORIGINS", "").split() if o
]

# ---- Application ------------------------------------------------------
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.humanize",     # intcomma for scan counter
    "scanner",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "scanner.middleware.SecurityHeadersMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "vibecheck.urls"

TEMPLATES = [
    {
        "BACKEND":  "django.template.backends.django.DjangoTemplates",
        "DIRS":     [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "vibecheck.wsgi.application"

# ---- Database ---------------------------------------------------------
_pg_host = os.environ.get("PGHOST")

if _pg_host:
    DATABASES = {
        "default": {
            "ENGINE":       "django.db.backends.postgresql",
            "NAME":         os.environ.get("PGDATABASE", "vibecheck"),
            "USER":         os.environ.get("PGUSER",     "postgres"),
            "PASSWORD":     os.environ.get("PGPASSWORD", ""),
            "HOST":         _pg_host,
            "PORT":         os.environ.get("PGPORT",     "5432"),
            "CONN_MAX_AGE": 60,
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE":  "django.db.backends.sqlite3",
            "NAME":    BASE_DIR / "db.sqlite3",
            "OPTIONS": {"timeout": 20},
        }
    }

# ---- Cache (rate limiter) ---------------------------------------------
#
# LocMemCache is per-process — with multiple gunicorn workers the
# 10/hr rate limit becomes 10 * workers per IP. Redis fixes this.
# Set REDIS_URL in production.
#
_redis_url = os.environ.get("REDIS_URL")

CACHES = {
    "default": (
        {
            "BACKEND":  "django.core.cache.backends.redis.RedisCache",
            "LOCATION": _redis_url,
        }
        if _redis_url else
        {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        }
    )
}

# ---- Sessions ---------------------------------------------------------
SESSION_COOKIE_AGE      = 60 * 60 * 24 * 90   # 90 days
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE   = not DEBUG

# ---- HTTPS hardening (production only) --------------------------------
if not DEBUG:
    SECURE_SSL_REDIRECT            = True
    SECURE_PROXY_SSL_HEADER        = ("HTTP_X_FORWARDED_PROTO", "https")
    SECURE_HSTS_SECONDS            = 31_536_000   # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD            = True
    CSRF_COOKIE_SECURE             = True

# ---- Static files -----------------------------------------------------
STATIC_URL   = "/static/"
STATIC_ROOT  = BASE_DIR / "staticfiles"
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

# ---- Auth password validators ----------------------------------------
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# ---- Internationalisation ---------------------------------------------
LANGUAGE_CODE = "en-us"
TIME_ZONE = 'Asia/Kathmandu'
USE_I18N      = True
USE_TZ        = True

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ---- Logging ----------------------------------------------------------
#
# Structured JSON to stdout in production so platforms (Heroku, Render,
# Railway, Datadog) can parse and index log fields automatically.
# Plain text in DEBUG mode for readability.

class _JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict = {
            "ts":      self.formatTime(record, self.datefmt),
            "level":   record.levelname,
            "logger":  record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = self.formatStack(record.stack_info)
        return json.dumps(payload)


LOGGING = {
    "version":                  1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": _JSONFormatter,
        },
        "simple": {
            "format": "{levelname} {name}: {message}",
            "style":  "{",
        },
    },
    "handlers": {
        "stdout": {
            "class":     "logging.StreamHandler",
            "formatter": "simple" if DEBUG else "json",
            "stream":    "ext://sys.stdout",
        },
    },
    "root": {
        "handlers": ["stdout"],
        "level":    "INFO",
    },
    "loggers": {
        "django":          {"level": "INFO",              "propagate": True},
        "django.request":  {"level": "WARNING",           "propagate": True},
        "django.security": {"level": "WARNING",           "propagate": True},
        "scanner":         {"level": "DEBUG" if DEBUG else "INFO", "propagate": True},
    },
}