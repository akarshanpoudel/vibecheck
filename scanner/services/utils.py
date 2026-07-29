"""Shared URL utilities used by forms.py and scanner.py."""
from urllib.parse import urlparse, urlunparse


def normalise_url(url: str) -> str:
    """
    Convert internationalized domain name labels to punycode ASCII.

    Closes the homograph attack vector where visually-similar Unicode
    characters (е vs e, etc.) could bypass hostname allow/block checks.

        münchen.example.com   →   xn--mnchen-3ya.example.com
        https://пример.испытание  →  https://xn--e1afmkfd.xn--80akhbyknj4f

    If encoding fails the original URL is returned unchanged — the
    validator downstream will reject genuinely malformed input.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return url

    # Fast path — already pure ASCII, nothing to encode
    try:
        hostname.encode("ascii")
        return url
    except UnicodeEncodeError:
        pass

    try:
        encoded = ".".join(
            label.encode("idna").decode("ascii") if label else ""
            for label in hostname.split(".")
        )
    except (UnicodeError, UnicodeDecodeError):
        return url  # leave as-is; URLValidator will reject it

    port    = parsed.port
    netloc  = f"{encoded}:{port}" if port else encoded
    return urlunparse(parsed._replace(netloc=netloc))