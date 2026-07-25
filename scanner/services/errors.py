"""
Translates raw requests/socket exceptions into one-line human messages.
Call friendly_error(exc) wherever a RequestException is caught.
"""
import requests


def friendly_error(exc: Exception) -> str:
    msg = str(exc).lower()

    if isinstance(exc, requests.exceptions.SSLError):
        return (
            "SSL certificate error — the site's HTTPS configuration may be broken. "
            "If you own the site, check your certificate is valid and not self-signed."
        )
    if isinstance(exc, requests.exceptions.TooManyRedirects):
        return "Redirect loop detected — the server kept redirecting without resolving."

    if isinstance(exc, requests.exceptions.ConnectionError):
        if "refused" in msg:
            return "Connection refused — nothing is listening at that address."
        if "name or service not known" in msg or "nodename nor servname" in msg or "getaddrinfo failed" in msg:
            return "Hostname couldn't be resolved — double-check the URL and try again."
        if "reset by peer" in msg or "connection reset" in msg:
            return "The connection was reset by the remote server."
        return "Could not connect to the server — it may be down or blocking automated requests."

    if isinstance(exc, requests.exceptions.Timeout):
        return f"Request timed out after {exc.request.url if hasattr(exc, 'request') and exc.request else 'the URL'} took too long to respond."

    if isinstance(exc, requests.exceptions.InvalidURL):
        return "That doesn't look like a valid URL."

    # SSRFError is a subclass of RequestException — its message is already clean.
    if type(exc).__name__ == "SSRFError":
        return str(exc)

    if isinstance(exc, requests.exceptions.RequestException):
        return "The page couldn't be fetched — the site may be down or blocking automated requests."

    return str(exc)