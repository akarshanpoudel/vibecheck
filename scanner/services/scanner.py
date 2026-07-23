"""
Core scanning logic for VibeCheck.

Given a target URL, this module:
  1. Fetches the HTML page.
  2. Discovers linked JS assets (script src) and fetches them too.
  3. Runs the regex pattern library against all fetched text to find
     exposed API keys/secrets.
  4. Extracts plausible API endpoint paths referenced in the JS
     (fetch/axios/XHR calls) and probes a safe, small subset of them
     with a harmless GET to see if they respond without auth.
  5. Checks CORS headers on the main page and probed endpoints.

This is intentionally conservative: it only issues GET requests to
URLs discovered directly in the page's own source, never brute-forces
or fuzzes paths, and caps the number of network calls it makes.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from .patterns import KEY_PATTERNS

USER_AGENT = "VibeCheckScanner/1.0 (+https://example.com/about-this-scanner)"
REQUEST_TIMEOUT = 8
MAX_JS_ASSETS = 12
MAX_ENDPOINT_PROBES = 8

# Patterns used to spot candidate API endpoints referenced inside JS source,
# e.g. fetch("/api/chat"), axios.post('https://x.com/api/x', ...)
ENDPOINT_HINT_RE = re.compile(
    r"""(?:fetch|axios(?:\.\w+)?|XMLHttpRequest.*?open)\s*\(\s*['"`]([^'"`]+)['"`]""",
    re.IGNORECASE,
)
# Also catch plain string literals that look like API paths
PATH_LITERAL_RE = re.compile(r"""['"`](/api/[A-Za-z0-9_\-/]+)['"`]""")


@dataclass
class Finding:
    finding_type: str  # "secret" | "open_endpoint" | "cors"
    title: str
    severity: str  # critical | high | medium | low
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
    def critical_count(self):
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self):
        return sum(1 for f in self.findings if f.severity == "high")

    @property
    def medium_count(self):
        return sum(1 for f in self.findings if f.severity == "medium")


def _get(url: str, **kwargs):
    headers = {"User-Agent": USER_AGENT}
    return requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT, **kwargs)


def _redact(secret: str) -> str:
    if len(secret) <= 10:
        return "*" * len(secret)
    return f"{secret[:6]}{'*' * (len(secret) - 10)}{secret[-4:]}"


def _scan_text_for_secrets(text: str, source_label: str) -> list[Finding]:
    findings = []
    for spec in KEY_PATTERNS:
        for match in spec["pattern"].finditer(text):
            raw = match.group(0)
            findings.append(
                Finding(
                    finding_type="secret",
                    title=f"{spec['name']} exposed in client-side source",
                    severity=spec["severity"],
                    evidence=_redact(raw),
                    location=source_label,
                    recommendation="",  # filled in by caller via recommendations module
                    category=spec["category"],
                )
            )
    return findings


def _discover_js_assets(html: str, base_url: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    urls = []
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            urls.append(urljoin(base_url, src))
    # de-dupe, keep order
    seen = set()
    deduped = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)
    return deduped[:MAX_JS_ASSETS]


def _discover_candidate_endpoints(js_text: str, base_url: str) -> list[str]:
    candidates = set()
    for m in ENDPOINT_HINT_RE.finditer(js_text):
        candidates.add(m.group(1))
    for m in PATH_LITERAL_RE.finditer(js_text):
        candidates.add(m.group(1))

    resolved = []
    for c in candidates:
        if c.startswith("http://") or c.startswith("https://"):
            resolved.append(c)
        elif c.startswith("/"):
            resolved.append(urljoin(base_url, c))
    # de-dupe
    return list(dict.fromkeys(resolved))[:MAX_ENDPOINT_PROBES]


def _check_cors(resp: requests.Response, location: str) -> Finding | None:
    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "")
    if acao == "*" or (acao and acao != "null"):
        if acao == "*" and acac.lower() == "true":
            severity = "high"
        elif acao == "*":
            severity = "medium"
        else:
            return None  # reflecting a specific origin isn't inherently a problem
        return Finding(
            finding_type="cors",
            title="Permissive CORS policy",
            severity=severity,
            evidence=f"Access-Control-Allow-Origin: {acao}"
            + (f", Access-Control-Allow-Credentials: {acac}" if acac else ""),
            location=location,
            recommendation="",
            category="cors",
        )
    return None


def _probe_endpoint(url: str) -> Finding | None:
    try:
        resp = _get(url)
    except requests.RequestException:
        return None

    finding = None
    if resp.status_code < 400:
        # Responded without an auth challenge. This is a heuristic signal,
        # not proof of vulnerability -- some endpoints are meant to be public.
        looks_sensitive = any(
            kw in url.lower() for kw in ("chat", "completion", "generate", "openai",
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


def run_scan(target_url: str) -> ScanResult:
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    result = ScanResult(target_url=target_url, ok=True)

    try:
        page_resp = _get(target_url)
    except requests.RequestException as exc:
        result.ok = False
        result.error = f"Could not fetch the page: {exc}"
        return result

    html = page_resp.text
    result.findings.extend(_scan_text_for_secrets(html, "Main HTML document"))

    cors_finding = _check_cors(page_resp, target_url)
    if cors_finding:
        result.findings.append(cors_finding)

    # Discover and scan JS assets
    js_urls = _discover_js_assets(html, target_url)
    all_js_text = ""
    for js_url in js_urls:
        try:
            js_resp = _get(js_url)
        except requests.RequestException:
            continue
        result.assets_scanned.append(js_url)
        js_text = js_resp.text
        all_js_text += "\n" + js_text
        result.findings.extend(_scan_text_for_secrets(js_text, js_url))
        time.sleep(0.05)  # be polite

    # Discover and probe candidate endpoints referenced in JS
    candidate_endpoints = _discover_candidate_endpoints(all_js_text, target_url)
    for ep in candidate_endpoints:
        # Only probe endpoints on the same host as the target, to avoid
        # poking third-party infrastructure (e.g. CDNs, analytics).
        if urlparse(ep).netloc != urlparse(target_url).netloc:
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
        time.sleep(0.05)

    return result
