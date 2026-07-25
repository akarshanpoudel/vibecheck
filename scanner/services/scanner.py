"""
Core scanning logic for VibeCheck.

  1. Validates every outbound URL against private/reserved IP ranges (SSRF).
  2. Fetches the HTML page.
  3. Discovers linked JS assets and fetches them concurrently.
  4. Runs the pattern library against all fetched text.
  5. Extracts and probes API endpoint paths found in JS.
  6. Checks CORS headers on the main page and probed endpoints.
  7. Deduplicates findings before returning.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from .patterns import KEY_PATTERNS

USER_AGENT        = "VibeCheckScanner/1.0 (+https://vibecheck.example.com/about)"
REQUEST_TIMEOUT   = 8
MAX_JS_ASSETS     = 12
MAX_ENDPOINT_PROBES = 8
JS_FETCH_WORKERS  = 6

ENDPOINT_HINT_RE = re.compile(
    r"""(?:fetch|axios(?:\.\w+)?|XMLHttpRequest.*?open)\s*\(\s*['\"`]([^'\"`]+)['\"`]""",
    re.IGNORECASE,
)
PATH_LITERAL_RE = re.compile(r"""['\"`](/api/[A-Za-z0-9_\-/]+)['\"`]""")


# ---------------------------------------------------------------------------
# SSRF protection
# ---------------------------------------------------------------------------

_BLOCKED_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    # IPv4
    ipaddress.ip_network("0.0.0.0/8"),          # "This" network
    ipaddress.ip_network("10.0.0.0/8"),          # RFC 1918
    ipaddress.ip_network("100.64.0.0/10"),       # Carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),         # Loopback
    ipaddress.ip_network("169.254.0.0/16"),      # Link-local — AWS/GCP metadata!
    ipaddress.ip_network("172.16.0.0/12"),       # RFC 1918
    ipaddress.ip_network("192.0.0.0/24"),        # IETF protocol assignments
    ipaddress.ip_network("192.168.0.0/16"),      # RFC 1918
    ipaddress.ip_network("198.18.0.0/15"),       # Benchmarking
    ipaddress.ip_network("224.0.0.0/4"),         # Multicast
    ipaddress.ip_network("240.0.0.0/4"),         # Reserved
    ipaddress.ip_network("255.255.255.255/32"),  # Broadcast
    # IPv6
    ipaddress.ip_network("::1/128"),             # Loopback
    ipaddress.ip_network("fc00::/7"),            # Unique local
    ipaddress.ip_network("fe80::/10"),           # Link-local
]

_BLOCKED_HOSTNAMES = frozenset({
    "localhost",
    "metadata.google.internal",  # GCP metadata
    "169.254.169.254",           # AWS / Azure / GCP metadata (as IP literal)
})


class SSRFError(requests.RequestException):
    """Raised when a URL resolves to a private or reserved address."""


def _check_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, hostname: str) -> None:
    for network in _BLOCKED_NETWORKS:
        if ip in network:
            raise SSRFError(
                f"Blocked: {hostname!r} resolves to a private/reserved address ({ip}). "
                "VibeCheck only scans publicly reachable URLs."
            )


def _assert_safe_url(url: str) -> None:
    """Resolve the hostname and reject any private/reserved destination."""
    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        raise SSRFError("Invalid URL: no hostname found.")

    if hostname.lower() in _BLOCKED_HOSTNAMES:
        raise SSRFError(
            f"Blocked: requests to {hostname!r} are not allowed (SSRF protection)."
        )

    # If the hostname is already an IP literal, check it directly.
    try:
        _check_ip(ipaddress.ip_address(hostname), hostname)
        return
    except ValueError:
        pass  # Not an IP literal — proceed to DNS resolution.

    try:
        results = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise SSRFError(f"Could not resolve {hostname!r}: {exc}") from exc

    for *_, sockaddr in results:
        try:
            _check_ip(ipaddress.ip_address(sockaddr[0]), hostname)
        except ValueError:
            continue


# ---------------------------------------------------------------------------
# Core data types
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    finding_type: str   # "secret" | "open_endpoint" | "cors"
    title: str
    severity: str       # critical | high | medium | low
    evidence: str
    location: str
    recommendation: str
    category: str = "generic"


@dataclass
class ScanResult:
    target_url: str
    ok: bool
    error: str | None = None
    findings: list[Finding] = field(default_factory=list)
    assets_scanned: list[str] = field(default_factory=list)
    endpoints_probed: list[str] = field(default_factory=list)

    @property
    def critical_count(self): return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self): return sum(1 for f in self.findings if f.severity == "high")

    @property
    def medium_count(self): return sum(1 for f in self.findings if f.severity == "medium")


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _get(url: str, **kwargs) -> requests.Response:
    """GET with SSRF check baked in. SSRFError is a subclass of RequestException."""
    _assert_safe_url(url)
    return requests.get(
        url,
        headers={"User-Agent": USER_AGENT},
        timeout=REQUEST_TIMEOUT,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Pattern scanning + deduplication
# ---------------------------------------------------------------------------

def _redact(secret: str) -> str:
    if len(secret) <= 10:
        return "*" * len(secret)
    return f"{secret[:6]}{'*' * (len(secret) - 10)}{secret[-4:]}"


def _scan_text_for_secrets(text: str, source_label: str) -> list[Finding]:
    findings = []
    for spec in KEY_PATTERNS:
        for match in spec["pattern"].finditer(text):
            raw = match.group(0)

            # Optional context guard — patterns can supply a `context` regex
            # that must match within `context_window` chars of the hit.
            # Used to tame noisy patterns (e.g. generic JWTs).
            ctx_re = spec.get("context")
            if ctx_re is not None:
                window = spec.get("context_window", 200)
                surrounding = text[max(0, match.start() - window): match.end() + window]
                if not ctx_re.search(surrounding):
                    continue

            findings.append(Finding(
                finding_type="secret",
                title=f"{spec['name']} exposed in client-side source",
                severity=spec["severity"],
                evidence=_redact(raw),
                location=source_label,
                recommendation="",
                category=spec["category"],
            ))
    return findings


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """
    Collapse redundant findings.

    A key that appears verbatim in several JS bundles would otherwise produce
    one finding per bundle. We keep the first occurrence only.
    """
    seen: set[tuple] = set()
    unique: list[Finding] = []
    for f in findings:
        # Secrets: same pattern match + same redacted value = same key
        # Endpoints/CORS: same type at the same URL = same issue
        key = (f.title, f.evidence) if f.finding_type == "secret" else (f.finding_type, f.location)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# ---------------------------------------------------------------------------
# Asset discovery + concurrent fetching
# ---------------------------------------------------------------------------

def _discover_js_assets(html: str, base_url: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    seen: set[str] = set()
    urls: list[str] = []
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            full = urljoin(base_url, src)
            if full not in seen:
                seen.add(full)
                urls.append(full)
    return urls[:MAX_JS_ASSETS]


def _fetch_js_asset(js_url: str) -> tuple[str, str] | None:
    """Fetch one JS bundle. Returns (url, text) or None on any error."""
    try:
        return js_url, _get(js_url).text
    except (requests.RequestException, SSRFError):
        return None


def _discover_candidate_endpoints(js_text: str, base_url: str) -> list[str]:
    candidates: set[str] = set()
    for m in ENDPOINT_HINT_RE.finditer(js_text):
        candidates.add(m.group(1))
    for m in PATH_LITERAL_RE.finditer(js_text):
        candidates.add(m.group(1))

    resolved: list[str] = []
    for c in candidates:
        if c.startswith(("http://", "https://")):
            resolved.append(c)
        elif c.startswith("/"):
            resolved.append(urljoin(base_url, c))
    return list(dict.fromkeys(resolved))[:MAX_ENDPOINT_PROBES]


# ---------------------------------------------------------------------------
# CORS + endpoint probing
# ---------------------------------------------------------------------------

def _check_cors(resp: requests.Response, location: str) -> Finding | None:
    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "")
    if acao == "*":
        severity = "high" if acac.lower() == "true" else "medium"
    elif acao and acao != "null":
        return None  # reflecting a specific origin isn't inherently a problem
    else:
        return None
    return Finding(
        finding_type="cors",
        title="Permissive CORS policy",
        severity=severity,
        evidence="Access-Control-Allow-Origin: " + acao + (f", Access-Control-Allow-Credentials: {acac}" if acac else ""),
        location=location,
        recommendation="",
        category="cors",
    )


def _probe_endpoint(url: str) -> tuple[Finding | None, requests.Response] | None:
    """Returns (finding_or_None, response) or None if the request failed."""
    try:
        resp = _get(url)
    except (requests.RequestException, SSRFError):
        return None

    finding = None
    if resp.status_code < 400:
        looks_sensitive = any(
            kw in url.lower()
            for kw in ("chat", "completion", "generate", "openai",
                       "anthropic", "llm", "ai", "gpt", "assistant")
        )
        finding = Finding(
            finding_type="open_endpoint",
            title="API endpoint responded without authentication",
            severity="high" if looks_sensitive else "medium",
            evidence=f"HTTP {resp.status_code} on GET {url}",
            location=url,
            recommendation="",
            category="open_endpoint",
        )
    return finding, resp


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_scan(target_url: str) -> ScanResult:
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    result = ScanResult(target_url=target_url, ok=True)

    try:
        page_resp = _get(target_url)
    except (requests.RequestException, SSRFError) as exc:
        result.ok = False
        result.error = str(exc)
        return result

    html = page_resp.text
    result.findings.extend(_scan_text_for_secrets(html, "Main HTML document"))

    cors_finding = _check_cors(page_resp, target_url)
    if cors_finding:
        result.findings.append(cors_finding)

    # Fetch all JS bundles concurrently instead of one-by-one
    js_urls = _discover_js_assets(html, target_url)
    all_js_text = ""

    with ThreadPoolExecutor(max_workers=JS_FETCH_WORKERS) as pool:
        futures = {pool.submit(_fetch_js_asset, url): url for url in js_urls}
        for future in as_completed(futures):
            fetch_result = future.result()
            if fetch_result is None:
                continue
            js_url, js_text = fetch_result
            result.assets_scanned.append(js_url)
            all_js_text += "\n" + js_text
            result.findings.extend(_scan_text_for_secrets(js_text, js_url))

    # Probe candidate endpoints (sequential — we're a guest on their server)
    target_netloc = urlparse(target_url).netloc
    for ep in _discover_candidate_endpoints(all_js_text, target_url):
        if urlparse(ep).netloc != target_netloc:
            continue  # only same-host probing
        probe = _probe_endpoint(ep)
        if probe is None:
            continue
        finding, resp = probe
        result.endpoints_probed.append(ep)
        if finding:
            result.findings.append(finding)
        cors_finding = _check_cors(resp, ep)
        if cors_finding:
            result.findings.append(cors_finding)

    result.findings = _deduplicate_findings(result.findings)
    return result