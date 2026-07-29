"""
Core scanning logic for VibeCheck.

Scan order (matters for deduplication — first occurrence of a key wins):
  1.  Inline <script> blocks      — specific per-block label
  2.  Next.js __NEXT_DATA__ blob  — explicit label for server-rendered props
  3.  Full HTML text              — catches data-* attrs, meta tags, etc.
  4.  CORS check on the page itself
  5.  External JS bundles         — fetched concurrently
  6.  API endpoint probing        — same-host only, sequential
  7.  Deduplication
"""
from __future__ import annotations

import ipaddress
import logging
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from .errors import friendly_error
from .patterns import KEY_PATTERNS

# Place executable variable assignments AFTER all imports
logger = logging.getLogger(__name__)


MAX_ASSET_BYTES = 5 * 1024 * 1024   # 5 MB hard cap per JS asset
USER_AGENT          = "VibeCheckScanner/1.0 (+https://vibecheck.example.com/about)"
REQUEST_TIMEOUT     = 8
MAX_JS_ASSETS       = 12
MAX_ENDPOINT_PROBES = 8
JS_FETCH_WORKERS    = 6

# Script types treated as executable JavaScript.
_JS_TYPES = frozenset({
    "", "text/javascript", "application/javascript",
    "text/ecmascript", "application/ecmascript", "module",
})

ENDPOINT_HINT_RE = re.compile(
    r"""(?:fetch|axios(?:\.\w+)?|XMLHttpRequest.*?open)\s*\(\s*['\"`]([^'\"`]+)['\"`]""",
    re.IGNORECASE,
)
PATH_LITERAL_RE = re.compile(r"""['\"`](/api/[A-Za-z0-9_\-/]+)['\"`]""")


# ---------------------------------------------------------------------------
# SSRF protection
# ---------------------------------------------------------------------------

_BLOCKED_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),      # link-local / cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

_BLOCKED_HOSTNAMES = frozenset({
    "localhost",
    "metadata.google.internal",
    "169.254.169.254",
})


class SSRFError(requests.RequestException):
    """Raised when a URL resolves to a private or reserved address."""


def _check_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, hostname: str) -> None:
    for net in _BLOCKED_NETWORKS:
        if ip in net:
            raise SSRFError(
                f"Blocked: {hostname!r} resolves to a private/reserved address ({ip}). "
                "VibeCheck only scans publicly reachable URLs."
            )


def _assert_safe_url(url: str) -> None:
    parsed   = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        raise SSRFError("Invalid URL: no hostname found.")

    if hostname.lower() in _BLOCKED_HOSTNAMES:
        raise SSRFError(f"Blocked: requests to {hostname!r} are not allowed (SSRF protection).")

    try:
        _check_ip(ipaddress.ip_address(hostname), hostname)
        return
    except ValueError:
        pass

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
    finding_type:   str
    title:          str
    severity:       str
    evidence:       str
    location:       str
    recommendation: str
    category:       str = "generic"
    confidence: str = "medium" 


@dataclass
class ScanResult:
    target_url:       str
    ok:               bool
    error:            str | None    = None
    findings:         list[Finding] = field(default_factory=list)
    assets_scanned:   list[str]     = field(default_factory=list)
    endpoints_probed: list[str]     = field(default_factory=list)

    @property
    def critical_count(self): return sum(1 for f in self.findings if f.severity == "critical")
    @property
    def high_count(self):     return sum(1 for f in self.findings if f.severity == "high")
    @property
    def medium_count(self):   return sum(1 for f in self.findings if f.severity == "medium")


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _get(url: str, **kwargs) -> requests.Response:
    """GET with SSRF check baked in."""
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
            raw    = match.group(0)
            ctx_re = spec.get("context")
            if ctx_re is not None:
                window      = spec.get("context_window", 200)
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
                confidence=spec.get("confidence", "medium"),
            ))
    return findings


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """
    Keep the first occurrence of each unique finding.

    For secrets: unique key = (title, redacted_evidence).
    Scanning inline blocks before full HTML means specific labels
    ("Inline script block #2") win over generic ones ("Main HTML document").

    For endpoints/CORS: unique key = (finding_type, location).
    """
    seen:   set[tuple] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.title, f.evidence) if f.finding_type == "secret" else (f.finding_type, f.location)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# ---------------------------------------------------------------------------
# HTML parsing helpers  (all accept a pre-built BeautifulSoup — parse once)
# ---------------------------------------------------------------------------

def _extract_inline_scripts(soup: BeautifulSoup) -> list[tuple[str, str]]:
    """
    Return (content, label) for every inline <script> block that contains JS.

    Excluded:
      • tags with src=""  — those are external bundles
      • id="__NEXT_DATA__" — handled by _extract_next_data
      • type="application/json", "application/ld+json", etc. — not JS
      • empty blocks
    """
    results: list[tuple[str, str]] = []
    idx = 1
    for tag in soup.find_all("script"):
        if tag.get("src"):
            continue
        if tag.get("id") == "__NEXT_DATA__":
            continue
        script_type = (tag.get("type") or "").strip().lower()
        if script_type not in _JS_TYPES:
            continue
        text = (tag.string or tag.get_text() or "").strip()
        if not text:
            continue
        results.append((text, f"Inline script block #{idx}"))
        idx += 1
    return results


def _extract_next_data(soup: BeautifulSoup) -> str | None:
    """
    Return the raw JSON text of Next.js's __NEXT_DATA__ blob, or None.

    Next.js injects a <script id="__NEXT_DATA__" type="application/json">
    block into every server-rendered page. It contains all props passed
    to getServerSideProps / getStaticProps — a common accidental key leak.
    """
    tag = soup.find("script", {"id": "__NEXT_DATA__"})
    if not tag:
        return None
    return (tag.string or tag.get_text() or "").strip() or None


def _detect_framework(soup: BeautifulSoup, html: str) -> str | None:
    """
    Best-effort framework detection for richer finding labels.
    Returns a short identifier or None.
    """
    if soup.find("script", {"id": "__NEXT_DATA__"}):
        return "Next.js"
    if "window.__nuxt__" in html or "__NUXT__" in html:
        return "Nuxt.js"
    if "window.__remixContext" in html:
        return "Remix"
    if "window.___gatsby" in html or "__gatsby" in html:
        return "Gatsby"
    return None


def _discover_js_assets(soup: BeautifulSoup, base_url: str) -> list[str]:
    """Return URLs of all external JS bundles linked from the page."""
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


# ---------------------------------------------------------------------------
# Asset fetching
# ---------------------------------------------------------------------------

def _fetch_js_asset(js_url: str) -> tuple[str, str] | None:
    """Fetch one JS bundle with a 5 MB size cap. Returns (url, text) or None."""
    try:
        resp = _get(js_url, stream=True)

        # Content-Length fast-reject (not always present, never trusted fully)
        try:
            cl = int(resp.headers.get("Content-Length", 0))
            if cl > MAX_ASSET_BYTES:
                logger.info("asset.skipped.too_large url=%s declared_bytes=%d", js_url, cl)
                resp.close()
                return None
        except (ValueError, TypeError):
            pass

        # Stream and accumulate with a hard ceiling
        chunks: list[bytes] = []
        total = 0
        for chunk in resp.iter_content(chunk_size=65_536):   # 64 KB chunks
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_ASSET_BYTES:
                logger.info("asset.truncated url=%s bytes_read=%d", js_url, total)
                resp.close()
                return None

        return js_url, b"".join(chunks).decode("utf-8", errors="replace")
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
    if acao != "*":
        return None
    severity = "high" if acac.lower() == "true" else "medium"
    return Finding(
        finding_type="cors",
        title="Permissive CORS policy",
        severity=severity,
        evidence=(
            "Access-Control-Allow-Origin: " + acao
            + (f", Access-Control-Allow-Credentials: {acac}" if acac else "")
        ),
        location=location,
        recommendation="",
        category="cors",
    )


def _probe_endpoint(url: str) -> tuple[Finding | None, requests.Response] | None:
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
        result.ok    = False
        result.error = friendly_error(exc)
        return result

    html = page_resp.text
    soup = BeautifulSoup(html, "html.parser")   # parse once, share everywhere

    # ------------------------------------------------------------------
    # 1. Inline <script> blocks — most specific labels, scanned first
    #    so deduplication keeps these over the "Main HTML document" label.
    # ------------------------------------------------------------------
    for script_text, label in _extract_inline_scripts(soup):
        result.findings.extend(_scan_text_for_secrets(script_text, label))

    # ------------------------------------------------------------------
    # 2. Next.js __NEXT_DATA__ — server-side props injected into HTML.
    #    Devs routinely pass secrets through getServerSideProps by mistake.
    # ------------------------------------------------------------------
    next_data = _extract_next_data(soup)
    if next_data:
        framework = _detect_framework(soup, html) or "Next.js"
        result.findings.extend(
            _scan_text_for_secrets(
                next_data,
                f"{framework} __NEXT_DATA__ blob (server-side props injected into page HTML)",
            )
        )

    # ------------------------------------------------------------------
    # 3. Full HTML — catches keys in data-* attributes, meta tags,
    #    og: tags, and any other non-script context.
    #    Deduplication means items already found above aren't double-reported.
    # ------------------------------------------------------------------
    result.findings.extend(_scan_text_for_secrets(html, "Main HTML document"))

    # ------------------------------------------------------------------
    # 4. CORS on the page itself
    # ------------------------------------------------------------------
    cors_finding = _check_cors(page_resp, target_url)
    if cors_finding:
        result.findings.append(cors_finding)

    # ------------------------------------------------------------------
    # 5. External JS bundles — fetched concurrently
    # ------------------------------------------------------------------
    js_urls     = _discover_js_assets(soup, target_url)
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

    # ------------------------------------------------------------------
    # 6. Endpoint probing — same-host only, sequential out of courtesy
    # ------------------------------------------------------------------
    target_netloc = urlparse(target_url).netloc
    for ep in _discover_candidate_endpoints(all_js_text, target_url):
        if urlparse(ep).netloc != target_netloc:
            continue
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

    # ------------------------------------------------------------------
    # 7. Deduplicate
    # ------------------------------------------------------------------
    result.findings = _deduplicate_findings(result.findings)
    return result