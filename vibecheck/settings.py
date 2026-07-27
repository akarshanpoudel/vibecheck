import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# ---- Security ----------------------------------------------------------
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

# ---- Application -------------------------------------------------------
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "scanner",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",       # serve static files in prod
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
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS":    [],
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

# ---- Database ----------------------------------------------------------
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

# ---- Cache (used by rate limiter) -------------------------------------
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        # In production with multiple workers, swap to Redis:
        # "BACKEND": "django.core.cache.backends.redis.RedisCache",
        # "LOCATION": os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/1"),
    }
}

# ---- Sessions ---------------------------------------------------------
SESSION_COOKIE_AGE      = 60 * 60 * 24 * 90   # 90 days
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE   = not DEBUG            # HTTPS-only in prod

# ---- Auth password validators -----------------------------------------
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# ---- Internationalisation ---------------------------------------------
LANGUAGE_CODE = "en-us"
TIME_ZONE     = "UTC"
USE_I18N      = True
USE_TZ        = True

# ---- Static files -----------------------------------------------------
STATIC_URL   = "/static/"
STATIC_ROOT  = BASE_DIR / "staticfiles"        # target dir for collectstatic
STATICFILES_STORAGE = (
    "whitenoise.storage.CompressedManifestStaticFilesStorage"
)

# ---- Misc -------------------------------------------------------------
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"