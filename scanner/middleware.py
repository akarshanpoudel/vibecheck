"""
SecurityHeadersMiddleware — applied to every response.

CSP uses 'unsafe-inline' for script-src because the result page embeds a
small polling snippet inline. Day-5 improvement: move it to a static JS
file and switch to a nonce.
"""


class SecurityHeadersMiddleware:
    _CSP = (
        "default-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'; "
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