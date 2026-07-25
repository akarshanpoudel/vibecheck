"""
Tests for the two most security-critical code paths:

  SSRFTests    — _assert_safe_url must block every private/reserved destination.
  PatternTests — each provider pattern must hit on a synthetic valid key
                 and miss on a clearly wrong string.

Run with: python manage.py test scanner
"""
from django.test import TestCase

from scanner.services.scanner import SSRFError, _assert_safe_url
from scanner.services.patterns import KEY_PATTERNS


# ---------------------------------------------------------------------------
# SSRF
# ---------------------------------------------------------------------------

class SSRFTests(TestCase):
    """
    All of these must raise SSRFError.
    None trigger DNS resolution — they're caught by hostname blocklist
    or IP-literal checks — so these tests work offline too.
    """

    BLOCKED = [
        "http://localhost/",
        "http://localhost:8080/api/chat",
        "http://127.0.0.1/",
        "http://127.0.0.1:3000/",
        "http://0.0.0.0/",
        "http://169.254.169.254/latest/meta-data/",   # AWS / Azure metadata
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


# ---------------------------------------------------------------------------
# Pattern matching
# ---------------------------------------------------------------------------

class PatternTests(TestCase):
    """
    Format: (name_fragment, [strings_that_must_match], [strings_that_must_not_match])

    Synthetic keys use repeated characters so they're obviously fake,
    but they satisfy each pattern's length/prefix constraints exactly.
    """

    # helpers
    @staticmethod
    def _a(n): return "A" * n
    @staticmethod
    def _x(n): return "a" * n   # lowercase hex-safe

    CASES = None  # populated in setUpClass to use the helpers cleanly

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        a = cls._a
        x = cls._x
        cls.CASES = [
            # (name_fragment, hits, misses)
            ("OpenAI",
             ["sk-" + a(25), "sk-proj-" + a(25)],
             ["sk-short", "not-a-key"]),

            ("Anthropic",
             ["sk-ant-" + a(25)],
             ["sk-ant-x"]),

            ("Gemini",
             ["AIza" + a(35)],
             ["AIzaShort"]),

            ("Cohere",
             ["co-" + a(40)],
             ["co-short"]),

            ("Hugging Face",
             ["hf_" + a(34)],
             ["hf_tiny"]),

            ("Groq",
             ["gsk_" + a(25)],
             ["gsk_tiny"]),

            ("Perplexity",
             ["pplx-" + a(32)],
             ["pplx-short"]),

            ("Replicate",
             ["r8_" + a(32)],
             ["r8_x"]),

            ("OpenRouter",
             ["sk-or-v1-" + a(25)],
             ["sk-or-v1-x"]),

            ("xAI",
             ["xai-" + a(45)],
             ["xai-short"]),

            ("Fireworks",
             ["fw_" + a(35)],
             ["fw_tiny"]),

            ("Tavily",
             ["tvly-" + a(35)],
             ["tvly-x"]),

            ("AWS",
             ["AKIA" + a(16), "ASIA" + a(16)],
             ["BKIA" + a(16), "AKIA" + a(3)]),

            ("Stripe Secret",
             ["sk_live_" + a(24)],
             ["sk_live_short"]),

            ("Stripe Restricted",
             ["rk_live_" + a(24)],
             ["rk_live_x"]),

            ("GitHub Personal",
             ["ghp_" + a(36), "gho_" + a(36)],
             ["ghp_short", "ghp_" + a(35)]),   # one char too short

            ("GitHub Fine-Grained",
             ["github_pat_" + a(82)],
             ["github_pat_" + a(10)]),

            ("Mapbox",
             ["pk.eyJ1" + a(25)],
             ["pk.eyJ0" + a(25)]),           # wrong claim letter

            ("SendGrid",
             ["SG." + a(22) + "." + a(43)],
             ["SG." + a(5) + "." + a(10)]),

            ("Resend",
             ["re_" + a(25)],
             ["re_x"]),

            ("Twilio",
             ["SK" + x(32)],
             ["SK" + x(5)]),
        ]

    def _find_spec(self, name_fragment: str):
        for spec in KEY_PATTERNS:
            if name_fragment.lower() in spec["name"].lower():
                return spec
        self.fail(f"No pattern found containing name fragment {name_fragment!r}")

    def test_patterns_hit_and_miss(self):
        for name_frag, hits, misses in self.CASES:
            spec = self._find_spec(name_frag)
            with self.subTest(pattern=name_frag):
                for s in hits:
                    self.assertIsNotNone(
                        spec["pattern"].search(s),
                        msg=f"[{name_frag}] should match {s!r}",
                    )
                for s in misses:
                    self.assertIsNone(
                        spec["pattern"].search(s),
                        msg=f"[{name_frag}] should NOT match {s!r}",
                    )