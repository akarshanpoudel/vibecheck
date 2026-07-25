"""
SecurityHeadersMiddleware — applied to every response.

With the polling script moved to main.js (a static file served from 'self'),
script-src no longer needs 'unsafe-inline'.
"""


class SecurityHeadersMiddleware:
    _CSP = (
        "default-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self'; "                           # ← no more 'unsafe-inline'
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response.setdefault("Content-Security-Policy", self._CSP)
        response.setdefault("Referrer-Policy",         "strict-origin-when-cross-origin")
        response.setdefault("X-Content-Type-Options",  "nosniff")
        response.setdefault("Permissions-Policy",      "geolocation=(), microphone=(), camera=()")
        return response