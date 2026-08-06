"""
VibeCheck test suite — Day 9 complete coverage.

  SSRFTests              — _assert_safe_url blocks private/reserved destinations
  PatternTests           — every provider pattern hits and misses correctly
  NormaliseURLTests      — IDN/punycode conversion
  ScannerServiceTests    — run_scan, _scan_text_for_secrets, deduplication
  ViewTests              — index, result, status, API, rate limiter, dedup, health
  MiddlewareTests        — security headers on 200 and 404
  CleanupScansTests      — management command logic
"""
from datetime import timedelta
from unittest.mock import MagicMock, patch

import requests

from django.core.cache import cache
from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from scanner.models import Finding, Scan
from scanner.services.patterns import KEY_PATTERNS
from scanner.services.scanner import (
    SSRFError,
    Finding as ScannerFinding,
    _assert_safe_url,
    _deduplicate_findings,
    _scan_text_for_secrets,
    run_scan,
)
from scanner.services.utils import normalise_url


# SSRF
class SSRFTests(TestCase):
    """
    Every URL must raise SSRFError.
    None of these trigger DNS — they're caught by hostname blocklist or
    IP-literal checks, so the tests work offline.
    """
    BLOCKED = [
        "http://localhost/",
        "http://localhost:8080/api/chat",
        "http://127.0.0.1/",
        "http://127.0.0.1:3000/",
        "http://0.0.0.0/",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/",
        "http://192.168.0.1/",
        "http://192.168.1.254/admin",
        "http://10.0.0.1/",
        "http://10.10.10.10/",
        "http://172.16.0.1/",
        "http://172.31.255.255/",
        "http://[::1]/",
        "http://[::1]:8000/",
        "http://metadata.google.internal/",
    ]

    def test_private_destinations_are_blocked(self):
        for url in self.BLOCKED:
            with self.subTest(url=url):
                with self.assertRaises(SSRFError, msg=f"{url!r} should have been blocked"):
                    _assert_safe_url(url)


# Patterns

class PatternTests(TestCase):
    """
    Format: (name_fragment, [must_match], [must_not_match])
    Synthetic keys use repeated characters — obviously fake but satisfy
    each pattern's length and prefix constraints exactly.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        a = lambda n: "A" * n   # noqa: E731
        x = lambda n: "a" * n   # noqa: E731
        cls.CASES = [
            ("OpenAI",            ["sk-" + a(25), "sk-proj-" + a(25)],  ["sk-x"]),
            ("Anthropic",         ["sk-ant-" + a(25)],                   ["sk-ant-x"]),
            ("Gemini",            ["AIza" + a(35)],                      ["AIzaShort"]),
            ("Cohere",            ["co-" + a(40)],                       ["co-x"]),
            ("Hugging Face",      ["hf_" + a(34)],                      ["hf_x"]),
            ("Groq",              ["gsk_" + a(25)],                      ["gsk_tiny"]),
            ("Perplexity",        ["pplx-" + a(32)],                     ["pplx-x"]),
            ("Replicate",         ["r8_" + a(32)],                       ["r8_x"]),
            ("OpenRouter",        ["sk-or-v1-" + a(25)],                 ["sk-or-v1-x"]),
            ("xAI",               ["xai-" + a(45)],                      ["xai-x"]),
            ("Fireworks",         ["fw_" + a(35)],                       ["fw_x"]),
            ("Tavily",            ["tvly-" + a(35)],                     ["tvly-x"]),
            ("AWS",               ["AKIA" + a(16), "ASIA" + a(16)],      ["BKIA" + a(16)]),
            ("Stripe Secret",     ["sk_live_" + a(24)],                  ["sk_live_x"]),
            ("Stripe Restricted", ["rk_live_" + a(24)],                  ["rk_live_x"]),
            ("GitHub Personal",   ["ghp_" + a(36), "gho_" + a(36)],     ["ghp_" + a(5)]),
            ("GitHub Fine",       ["github_pat_" + a(82)],               ["github_pat_" + a(5)]),
            ("Mapbox",            ["pk.eyJ1" + a(25)],                   ["pk.eyJ0" + a(25)]),
            ("SendGrid",          ["SG." + a(22) + "." + a(43)],         ["SG." + a(3) + "." + a(5)]),
            ("Resend",            ["re_" + a(25)],                       ["re_x"]),
            ("Twilio",            ["SK" + x(32)],                        ["SK" + x(5)]),
        ]

    def _find_spec(self, fragment: str):
        for spec in KEY_PATTERNS:
            if fragment.lower() in spec["name"].lower():
                return spec
        self.fail(f"No pattern found containing {fragment!r}")

    def test_patterns_hit_and_miss(self):
        for name_frag, hits, misses in self.CASES:
            spec = self._find_spec(name_frag)
            with self.subTest(pattern=name_frag):
                for s in hits:
                    self.assertIsNotNone(spec["pattern"].search(s),
                                        msg=f"[{name_frag}] should match {s!r}")
                for s in misses:
                    self.assertIsNone(spec["pattern"].search(s),
                                      msg=f"[{name_frag}] should NOT match {s!r}")

    def test_every_pattern_has_confidence_field(self):
        for spec in KEY_PATTERNS:
            with self.subTest(pattern=spec["name"]):
                self.assertIn(
                    spec.get("confidence"),
                    ("high", "medium", "low"),
                    msg=f"{spec['name']} is missing a valid confidence value",
                )

# URL normalisation

class NormaliseURLTests(TestCase):

    def test_ascii_hostname_is_unchanged(self):
        url = "https://example.com/path?q=1"
        self.assertEqual(normalise_url(url), url)

    def test_cyrillic_hostname_converts_to_punycode(self):
        url = "https://пример.испытание/"
        result = normalise_url(url)
        self.assertNotIn("п", result)
        self.assertIn("xn--", result)

    def test_umlaut_hostname_converts_to_punycode(self):
        url = "https://münchen.de/"
        result = normalise_url(url)
        self.assertIn("xn--", result)
        self.assertIn(".de", result)

    def test_no_hostname_returns_unchanged(self):
        bad = "not-a-url"
        self.assertEqual(normalise_url(bad), bad)

    def test_path_and_query_preserved(self):
        url = "https://example.com/api/v1?key=val&other=123"
        self.assertEqual(normalise_url(url), url)

    def test_port_preserved(self):
        url = "https://example.com:8443/path"
        self.assertEqual(normalise_url(url), url)


# Scanner service

class ScannerServiceTests(TestCase):
    """
    All network calls are mocked at _get so tests run offline instantly.
    Each test controls exactly what the scanner "sees" from the network.
    """

    def _mock_response(self, html: str = "", headers: dict | None = None) -> MagicMock:
        resp = MagicMock()
        resp.text          = html
        resp.headers       = headers or {}
        resp.status_code   = 200
        return resp

    # run_scan 

    @patch("scanner.services.scanner._get")
    def test_clean_page_produces_no_findings(self, mock_get):
        mock_get.return_value = self._mock_response("<html><body>Hello</body></html>")
        result = run_scan("https://example.com")
        self.assertTrue(result.ok)
        self.assertEqual(len(result.findings), 0)
        self.assertIsNone(result.error)

    @patch("scanner.services.scanner._get")
    def test_embedded_anthropic_key_is_detected(self, mock_get):
        fake_key = "sk-ant-" + "a" * 25
        html = f'<html><body><script>const KEY="{fake_key}"</script></body></html>'
        mock_get.return_value = self._mock_response(html)

        result = run_scan("https://example.com")

        self.assertTrue(result.ok)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].category, "llm")
        self.assertEqual(result.findings[0].severity, "critical")
        self.assertEqual(result.findings[0].confidence, "high")

    @patch("scanner.services.scanner._get")
    def test_connection_refused_returns_friendly_error(self, mock_get):
        mock_get.side_effect = requests.exceptions.ConnectionError("Connection refused")
        result = run_scan("https://example.com")
        self.assertFalse(result.ok)
        self.assertIn("refused", result.error.lower())

    @patch("scanner.services.scanner._get")
    def test_timeout_returns_friendly_error(self, mock_get):
        mock_get.side_effect = requests.exceptions.Timeout()
        result = run_scan("https://example.com")
        self.assertFalse(result.ok)
        self.assertIsNotNone(result.error)

    @patch("scanner.services.scanner._get")
    def test_permissive_cors_produces_finding(self, mock_get):
        mock_get.return_value = self._mock_response(
            "<html><body></body></html>",
            headers={"Access-Control-Allow-Origin": "*"},
        )
        result = run_scan("https://example.com")
        cors_findings = [f for f in result.findings if f.finding_type == "cors"]
        self.assertEqual(len(cors_findings), 1)

    @patch("scanner.services.scanner._get")
    def test_wildcard_cors_with_credentials_is_critical(self, mock_get):
        mock_get.return_value = self._mock_response(
            "<html></html>",
            headers={
                "Access-Control-Allow-Origin":      "*",
                "Access-Control-Allow-Credentials": "true",
            },
        )
        result = run_scan("https://example.com")
        cors_findings = [f for f in result.findings if f.finding_type == "cors"]
        self.assertEqual(len(cors_findings), 1)
        self.assertEqual(cors_findings[0].severity, "high")

    # _scan_text_for_secrets 

    def test_scan_text_detects_openai_key(self):
        fake = "sk-" + "a" * 25
        findings = _scan_text_for_secrets(f'var k="{fake}"', "test.js")
        self.assertTrue(any(f.category == "llm" for f in findings))

    def test_scan_text_returns_correct_confidence(self):
        fake = "sk-ant-" + "a" * 25
        findings = _scan_text_for_secrets(f'const k="{fake}"', "test.js")
        self.assertTrue(all(f.confidence == "high" for f in findings))

    def test_scan_text_clean_source_has_no_findings(self):
        findings = _scan_text_for_secrets(
            "const greeting = 'Hello, world! How are you today?';",
            "test.js",
        )
        self.assertEqual(len(findings), 0)

    def test_scan_text_redacts_evidence(self):
        fake = "sk-" + "a" * 25
        findings = _scan_text_for_secrets(f'var k="{fake}"', "test.js")
        self.assertTrue(len(findings) > 0)
        # Evidence must be redacted — raw key must not appear
        self.assertNotIn(fake, findings[0].evidence)
        self.assertIn("*", findings[0].evidence)

    # Deduplication 

    def _make_finding(self, evidence: str, location: str) -> ScannerFinding:
        return ScannerFinding(
            finding_type="secret",
            title="OpenAI API Key exposed in client-side source",
            severity="critical",
            evidence=evidence,
            location=location,
            recommendation="",
            category="llm",
            confidence="high",
        )

    def test_same_key_in_multiple_files_deduped_to_one(self):
        findings = [
            self._make_finding("sk-AAAA****BBBB", "bundle1.js"),
            self._make_finding("sk-AAAA****BBBB", "bundle2.js"),  # same key, different file
        ]
        unique = _deduplicate_findings(findings)
        self.assertEqual(len(unique), 1)

    def test_different_keys_both_kept(self):
        findings = [
            self._make_finding("sk-AAAA****BBBB", "bundle1.js"),
            self._make_finding("sk-CCCC****DDDD", "bundle1.js"),  # different key
        ]
        unique = _deduplicate_findings(findings)
        self.assertEqual(len(unique), 2)

    def test_empty_findings_list_returns_empty(self):
        self.assertEqual(_deduplicate_findings([]), [])



# Views


class ViewTests(TestCase):

    def setUp(self):
        cache.clear()

    # Index 

    def test_index_get_returns_200(self):
        resp = self.client.get(reverse("scanner:index"))
        self.assertEqual(resp.status_code, 200)

    @patch("scanner.views.start_scan")
    def test_index_post_creates_pending_scan_and_redirects(self, mock_start):
        resp = self.client.post(
            reverse("scanner:index"),
            {"target_url": "https://example.com"},
        )
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(Scan.objects.count(), 1)
        scan = Scan.objects.first()
        self.assertEqual(scan.status, Scan.STATUS_PENDING)
        self.assertEqual(scan.target_url, "https://example.com")
        mock_start.assert_called_once()

    @patch("scanner.views.start_scan")
    def test_bare_domain_gets_https_prepended(self, mock_start):
        self.client.post(reverse("scanner:index"), {"target_url": "example.com"})
        scan = Scan.objects.first()
        self.assertIsNotNone(scan)
        self.assertTrue(scan.target_url.startswith("https://"))

    def test_localhost_is_rejected_by_form(self):
        resp = self.client.post(
            reverse("scanner:index"),
            {"target_url": "http://localhost/"},
        )
        self.assertEqual(resp.status_code, 200)  
        self.assertEqual(Scan.objects.count(), 0)

    def test_index_shows_scan_counter(self):
        Scan.objects.create(
            target_url="https://example.com",
            status=Scan.STATUS_COMPLETE,
            ok=True,
        )
        resp = self.client.get(reverse("scanner:index"))
        self.assertContains(resp, "URL scanned")

    # Deduplication 

    @patch("scanner.views.start_scan")
    def test_duplicate_submission_reuses_existing_scan(self, mock_start):
        existing = Scan.objects.create(
            target_url="https://example.com",
            status=Scan.STATUS_PENDING,
        )

        resp = self.client.post(
            reverse("scanner:index"),
            {"target_url": "https://example.com"},
        )

        self.assertEqual(resp.status_code, 302)
        self.assertEqual(Scan.objects.count(), 1)     
        mock_start.assert_not_called()                
        self.assertIn(existing.slug, resp["Location"])

    @patch("scanner.views.start_scan")
    def test_old_scan_outside_window_gets_new_scan(self, mock_start):
        old = Scan.objects.create(
            target_url="https://example.com",
            status=Scan.STATUS_COMPLETE,
        )
        # Push created_at outside the dedup window
        Scan.objects.filter(pk=old.pk).update(
            created_at=timezone.now() - timedelta(seconds=120)
        )

        self.client.post(
            reverse("scanner:index"),
            {"target_url": "https://example.com"},
        )

        self.assertEqual(Scan.objects.count(), 2)     
        mock_start.assert_called_once()

    # Result 

    def test_result_clean_scan(self):
        scan = Scan.objects.create(
            target_url="https://example.com",
            status=Scan.STATUS_COMPLETE,
            ok=True,
        )
        resp = self.client.get(reverse("scanner:result", args=[scan.slug]))
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.context["is_clean"])

    def test_result_with_findings(self):
        scan = Scan.objects.create(
            target_url="https://example.com",
            status=Scan.STATUS_COMPLETE,
            ok=True,
        )
        Finding.objects.create(
            scan=scan,
            finding_type="secret",
            title="OpenAI API Key exposed",
            severity="critical",
            confidence="high",
            evidence="sk-AAAA****",
            location="main.js",
            recommendation="Rotate immediately.",
            category="llm",
        )
        resp = self.client.get(reverse("scanner:result", args=[scan.slug]))
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.context["is_clean"])
        self.assertEqual(len(resp.context["llm_findings"]), 1)

    def test_result_pending_scan_shows_indicator(self):
        scan = Scan.objects.create(
            target_url="https://example.com",
            status=Scan.STATUS_PENDING,
        )
        resp = self.client.get(reverse("scanner:result", args=[scan.slug]))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "vc-pending")

    def test_result_failed_scan_shows_error_message(self):
        scan = Scan.objects.create(
            target_url="https://example.com",
            status=Scan.STATUS_FAILED,
            ok=False,
            error="Connection refused.",
        )
        resp = self.client.get(reverse("scanner:result", args=[scan.slug]))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Connection refused")

    def test_result_nonexistent_slug_returns_404(self):
        resp = self.client.get(reverse("scanner:result", args=["no-such-slug"]))
        self.assertEqual(resp.status_code, 404)

    # Status 

    def test_scan_status_returns_json(self):
        scan = Scan.objects.create(
            target_url="https://example.com",
            status=Scan.STATUS_PENDING,
        )
        resp = self.client.get(reverse("scanner:status", args=[scan.slug]))
        self.assertEqual(resp.status_code, 200)
        self.assertIn("application/json", resp["Content-Type"])
        self.assertEqual(resp.json(), {"status": "pending"})

    # API 

    def test_api_result_complete_scan_with_findings(self):
        scan = Scan.objects.create(
            target_url="https://example.com",
            status=Scan.STATUS_COMPLETE,
            ok=True,
        )
        Finding.objects.create(
            scan=scan,
            finding_type="secret",
            title="OpenAI API Key exposed",
            severity="critical",
            confidence="high",
            evidence="sk-AAAA****",
            location="main.js",
            recommendation="Rotate immediately.",
            category="llm",
        )
        resp = self.client.get(reverse("scanner:api_result", args=[scan.slug]))
        self.assertEqual(resp.status_code, 200)
        self.assertIn("application/json", resp["Content-Type"])

        data = resp.json()
        self.assertEqual(data["target_url"], "https://example.com")
        self.assertEqual(data["status"], "complete")
        self.assertEqual(data["summary"]["critical"], 1)
        self.assertEqual(data["summary"]["total"], 1)
        self.assertEqual(len(data["findings"]), 1)
        self.assertEqual(data["findings"][0]["confidence"], "high")

    def test_api_result_pending_scan_returns_empty_findings(self):
        scan = Scan.objects.create(
            target_url="https://example.com",
            status=Scan.STATUS_PENDING,
        )
        resp = self.client.get(reverse("scanner:api_result", args=[scan.slug]))
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "pending")
        self.assertEqual(data["findings"], [])
        self.assertEqual(data["summary"]["total"], 0)

    def test_api_result_nonexistent_slug_returns_404(self):
        resp = self.client.get(reverse("scanner:api_result", args=["no-such-slug"]))
        self.assertEqual(resp.status_code, 404)

    # Health 

    def test_health_endpoint_returns_ok(self):
        resp = self.client.get(reverse("scanner:health"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"ok": True})

    # Rate limiter 

    @patch("scanner.views.start_scan")
    @patch("scanner.decorators.SCAN_RATE_LIMIT", 2)
    def test_rate_limiter_returns_429_after_limit(self, mock_start):
        for _ in range(2):
            self.client.post(
                reverse("scanner:index"),
                {"target_url": "https://example.com"},
            )
        resp = self.client.post(
            reverse("scanner:index"),
            {"target_url": "https://example.com"},
        )
        self.assertEqual(resp.status_code, 429)

    # robots.txt 

    def test_robots_txt_returns_200_with_correct_content(self):
        resp = self.client.get("/robots.txt")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/plain", resp["Content-Type"])
        body = resp.content.decode()
        self.assertIn("Disallow: /scan/", body)
        self.assertIn("Disallow: /admin/", body)

# Middleware


class MiddlewareTests(TestCase):

    def test_csp_header_present_on_200(self):
        resp = self.client.get(reverse("scanner:index"))
        self.assertIn("Content-Security-Policy", resp)

    def test_csp_header_present_on_404(self):
        resp = self.client.get("/this-page-does-not-exist/")
        self.assertIn("Content-Security-Policy", resp)

    def test_referrer_policy_set(self):
        resp = self.client.get(reverse("scanner:index"))
        self.assertEqual(resp.get("Referrer-Policy"), "strict-origin-when-cross-origin")

    def test_x_content_type_options_nosniff(self):
        resp = self.client.get(reverse("scanner:index"))
        self.assertEqual(resp.get("X-Content-Type-Options"), "nosniff")

    def test_permissions_policy_set(self):
        resp = self.client.get(reverse("scanner:index"))
        self.assertIn("Permissions-Policy", resp)

    def test_csp_does_not_include_unsafe_inline(self):
        resp = self.client.get(reverse("scanner:index"))
        csp = resp.get("Content-Security-Policy", "")
        self.assertNotIn("'unsafe-inline'", csp)

    def test_frame_ancestors_none_in_csp(self):
        resp = self.client.get(reverse("scanner:index"))
        csp = resp.get("Content-Security-Policy", "")
        self.assertIn("frame-ancestors 'none'", csp)



# Management command — cleanup_scans

class CleanupScansTests(TestCase):

    def _make_old_pending(self, minutes_ago: int = 10) -> Scan:
        scan = Scan.objects.create(
            target_url="https://example.com",
            status=Scan.STATUS_PENDING,
        )
        Scan.objects.filter(pk=scan.pk).update(
            created_at=timezone.now() - timedelta(minutes=minutes_ago)
        )
        return scan

    def test_old_pending_scan_is_marked_failed(self):
        scan = self._make_old_pending(minutes_ago=10)

        call_command("cleanup_scans", verbosity=0)

        scan.refresh_from_db()
        self.assertEqual(scan.status, Scan.STATUS_FAILED)
        self.assertFalse(scan.ok)

    def test_recent_pending_scan_is_left_alone(self):
        scan = Scan.objects.create(
            target_url="https://example.com",
            status=Scan.STATUS_PENDING,
        )

        call_command("cleanup_scans", verbosity=0)

        scan.refresh_from_db()
        self.assertEqual(scan.status, Scan.STATUS_PENDING)

    def test_dry_run_makes_no_database_writes(self):
        scan = self._make_old_pending(minutes_ago=10)

        call_command("cleanup_scans", dry_run=True, verbosity=0)

        scan.refresh_from_db()
        self.assertEqual(scan.status, Scan.STATUS_PENDING)   # untouched

    def test_max_age_days_deletes_old_scans(self):
        old = Scan.objects.create(
            target_url="https://example.com",
            status=Scan.STATUS_COMPLETE,
        )
        Scan.objects.filter(pk=old.pk).update(
            created_at=timezone.now() - timedelta(days=40)
        )

        call_command("cleanup_scans", max_age_days=30, verbosity=0)

        self.assertFalse(Scan.objects.filter(pk=old.pk).exists())

    def test_max_age_days_keeps_recent_scans(self):
        recent = Scan.objects.create(
            target_url="https://example.com",
            status=Scan.STATUS_COMPLETE,
        )

        call_command("cleanup_scans", max_age_days=30, verbosity=0)

        self.assertTrue(Scan.objects.filter(pk=recent.pk).exists())

    def test_findings_cascade_deleted_with_scan(self):
        old = Scan.objects.create(
            target_url="https://example.com",
            status=Scan.STATUS_COMPLETE,
        )
        Finding.objects.create(
            scan=old,
            finding_type="secret",
            title="Test",
            severity="high",
            confidence="high",
            evidence="sk-AAAA****",
            location="main.js",
            recommendation="Rotate.",
            category="llm",
        )
        Scan.objects.filter(pk=old.pk).update(
            created_at=timezone.now() - timedelta(days=40)
        )

        call_command("cleanup_scans", max_age_days=30, verbosity=0)

        self.assertEqual(Finding.objects.count(), 0)