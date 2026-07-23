"""
IP-based rate limiter for scan form submissions.
Uses Django's cache framework (LocMemCache in dev, Redis/Memcached in prod).
"""
from functools import wraps

from django.core.cache import cache
from django.shortcuts import render

SCAN_RATE_LIMIT = 10   # max scans per window per IP
SCAN_RATE_WINDOW = 3600  # seconds (1 hour)


def _client_ip(request: object) -> str:
    xff = request.META.get("HTTP_X_FORWARDED_FOR", "")
    return xff.split(",")[0].strip() if xff else request.META.get("REMOTE_ADDR", "")


def scan_rate_limit(view_func):
    """Decorator — apply to any view that accepts scan form POSTs."""
    @wraps(view_func)
    def wrapped(request, *args, **kwargs):
        if request.method == "POST":
            ip = _client_ip(request)
            key = f"vc:rl:{ip}"
            count = cache.get(key, 0)
            if count >= SCAN_RATE_LIMIT:
                return render(
                    request,
                    "scanner/rate_limited.html",
                    {
                        "limit": SCAN_RATE_LIMIT,
                        "retry_after": SCAN_RATE_WINDOW // 60,
                    },
                    status=429,
                )
            if count == 0:
                cache.set(key, 1, SCAN_RATE_WINDOW)
            else:
                cache.incr(key)
        return view_func(request, *args, **kwargs)
    return wrapped