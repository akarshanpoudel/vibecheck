"""
Tests for VibeCheck.

SSRFTests    — _assert_safe_url blocks every private/reserved destination.
PatternTests — each provider pattern hits on synthetic valid keys, misses on wrong ones.
ViewTests    — key request/response paths: index, result, status, rate limiter, health.
"""
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse

from scanner.models import Finding, Scan
from scanner.services.scanner import SSRFError, _assert_safe_url
from scanner.services.patterns import KEY_PATTERNS


# ---------------------------------------------------------------------------
# SSRF
# ---------------------------------------------------------------------------

class SSRFTests(TestCase):
    BLOCKED = [
        "http://localhost/",
        "http://localhost:8080/api/chat",
        "http://127.0.0.1/",
        "http://0.0.0.0/",
        "http://169.254.169.254/latest/meta-data/",
        "http://192.168.0.1/",
        "http://10.0.0.1/",
        "http://172.16.0.1/",
        "http://[::1]/",
        "http://metadata.google.internal/",
    ]

    def test_private_destinations_are_blocked(self):
        for url in self.BLOCKED:
            with self.subTest(url=url):
                with self.assertRaises(SSRFError):
                    _assert_safe_url(url)


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

class PatternTests(TestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        a = lambda n: "A" * n   # noqa: E731
        x = lambda n: "a" * n   # noqa: E731
        cls.CASES = [
            ("OpenAI",            ["sk-" + a(25), "sk-proj-" + a(25)],           ["sk-x"]),
            ("Anthropic",         ["sk-ant-" + a(25)],                            ["sk-ant-x"]),
            ("Gemini",            ["AIza" + a(35)],                               ["AIzaShort"]),
            ("Cohere",            ["co-" + a(40)],                                ["co-x"]),
            ("Hugging Face",      ["hf_" + a(34)],                               ["hf_x"]),
            ("Groq",              ["gsk_" + a(25)],                               ["gsk_tiny"]),
            ("Perplexity",        ["pplx-" + a(32)],                              ["pplx-x"]),
            ("Replicate",         ["r8_" + a(32)],                                ["r8_x"]),
            ("OpenRouter",        ["sk-or-v1-" + a(25)],                          ["sk-or-v1-x"]),
            ("xAI",               ["xai-" + a(45)],                               ["xai-x"]),
            ("Fireworks",         ["fw_" + a(35)],                                ["fw_x"]),
            ("Tavily",            ["tvly-" + a(35)],                              ["tvly-x"]),
            ("AWS",               ["AKIA" + a(16), "ASIA" + a(16)],               ["BKIA" + a(16)]),
            ("Stripe Secret",     ["sk_live_" + a(24)],                           ["sk_live_x"]),
            ("Stripe Restricted", ["rk_live_" + a(24)],                           ["rk_live_x"]),
            ("GitHub Personal",   ["ghp_" + a(36), "gho_" + a(36)],              ["ghp_" + a(5)]),
            ("GitHub Fine",       ["github_pat_" + a(82)],                        ["github_pat_" + a(5)]),
            ("Mapbox",            ["pk.eyJ1" + a(25)],                            ["pk.eyJ0" + a(25)]),
            ("SendGrid",          ["SG." + a(22) + "." + a(43)],                  ["SG." + a(3) + "." + a(5)]),
            ("Resend",            ["re_" + a(25)],                                ["re_x"]),
            ("Twilio",            ["SK" + x(32)],                                 ["SK" + x(5)]),
        ]

    def _find_spec(self, name_fragment: str):
        for spec in KEY_PATTERNS:
            if name_fragment.lower() in spec["name"].lower():
                return spec
        self.fail(f"No pattern found containing {name_fragment!r}")

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


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------

class ViewTests(TestCase):

    def setUp(self):
        # Each test starts with a clean cache so rate limit counts don't bleed.
        cache.clear()

    # ---- Index ----------------------------------------------------------

    def test_index_get_returns_200(self):
        resp = self.client.get(reverse("scanner:index"))
        self.assertEqual(resp.status_code, 200)

    @patch("scanner.views.start_scan")
    def test_index_post_valid_url_creates_pending_scan_and_redirects(self, mock_start):
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
    def test_index_post_auto_prepends_https_scheme(self, mock_start):
        self.client.post(
            reverse("scanner:index"),
            {"target_url": "example.com"},
        )
        scan = Scan.objects.first()
        self.assertIsNotNone(scan)
        self.assertTrue(scan.target_url.startswith("https://"))

    def test_index_post_localhost_rejected(self):
        resp = self.client.post(
            reverse("scanner:index"),
            {"target_url": "http://localhost/"},
        )
        # Form error, not a redirect — no scan created.
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

    # ---- Result ---------------------------------------------------------

    def test_result_clean_scan(self):
        scan = Scan.objects.create(
            target_url="https://example.com",
            status=Scan.STATUS_COMPLETE,
            ok=True,
        )
        resp = self.client.get(reverse("scanner:result", args=[scan.slug]))
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.context["is_clean"])

    def test_result_pending_scan_shows_indicator(self):
        scan = Scan.objects.create(
            target_url="https://example.com",
            status=Scan.STATUS_PENDING,
        )
        resp = self.client.get(reverse("scanner:result", args=[scan.slug]))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "vc-pending")

    def test_result_failed_scan_shows_error(self):
        scan = Scan.objects.create(
            target_url="https://example.com",
            status=Scan.STATUS_FAILED,
            ok=False,
            error="Connection refused.",
        )
        resp = self.client.get(reverse("scanner:result", args=[scan.slug]))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Connection refused")

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
            evidence="sk-AAAA****BBBB",
            location="https://example.com/main.js",
            recommendation="Rotate the key immediately.",
            category="llm",
        )
        resp = self.client.get(reverse("scanner:result", args=[scan.slug]))
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.context["is_clean"])
        self.assertEqual(len(resp.context["llm_findings"]), 1)

    def test_result_nonexistent_slug_returns_404(self):
        resp = self.client.get(reverse("scanner:result", args=["no-such-slug"]))
        self.assertEqual(resp.status_code, 404)

    # ---- Status ---------------------------------------------------------

    def test_scan_status_returns_json(self):
        scan = Scan.objects.create(
            target_url="https://example.com",
            status=Scan.STATUS_PENDING,
        )
        resp = self.client.get(reverse("scanner:status", args=[scan.slug]))
        self.assertEqual(resp.status_code, 200)
        self.assertIn("application/json", resp["Content-Type"])
        self.assertEqual(resp.json(), {"status": "pending"})

    # ---- Health ---------------------------------------------------------

    def test_health_endpoint(self):
        resp = self.client.get(reverse("scanner:health"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"ok": True})

    # ---- Rate limiter ---------------------------------------------------

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