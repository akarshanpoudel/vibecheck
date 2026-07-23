"""
Pattern library for detecting exposed API keys and secrets in client-side
(HTML/JS) source. Focused on LLM provider keys, since that's the #1 way
vibecoded apps leak money-bleeding credentials, plus common
general-purpose cloud/service keys for broader coverage.

Each entry:
    name        -> human readable provider/service name
    pattern     -> compiled regex
    severity    -> "critical" | "high" | "medium"
    category    -> "llm" | "cloud" | "payment" | "generic"
"""
import re

KEY_PATTERNS = [
    # ---- LLM providers (primary focus) ----
    dict(
        name="OpenAI API Key",
        pattern=re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
        severity="critical",
        category="llm",
    ),
    dict(
        name="Anthropic API Key",
        pattern=re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
        severity="critical",
        category="llm",
    ),
    dict(
        name="Google Gemini / Generic Google API Key",
        pattern=re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        severity="critical",
        category="llm",
    ),
    dict(
        name="Cohere API Key",
        pattern=re.compile(r"\bco-[A-Za-z0-9]{40,}\b"),
        severity="critical",
        category="llm",
    ),
    dict(
        name="Hugging Face Token",
        pattern=re.compile(r"\bhf_[A-Za-z0-9]{34,}\b"),
        severity="critical",
        category="llm",
    ),
    dict(
        name="Mistral API Key",
        pattern=re.compile(r"\bmis-[A-Za-z0-9]{32,}\b"),
        severity="high",
        category="llm",
    ),
    dict(
        name="Groq API Key",
        pattern=re.compile(r"\bgsk_[A-Za-z0-9]{20,}\b"),
        severity="critical",
        category="llm",
    ),
    dict(
        name="Perplexity API Key",
        pattern=re.compile(r"\bpplx-[A-Za-z0-9]{32,}\b"),
        severity="critical",
        category="llm",
    ),
    dict(
        name="Replicate API Token",
        pattern=re.compile(r"\br8_[A-Za-z0-9]{32,}\b"),
        severity="critical",
        category="llm",
    ),
    dict(
        name="ElevenLabs API Key",
        pattern=re.compile(r"\b[a-f0-9]{32}\b(?=.{0,40}elevenlabs)", re.IGNORECASE),
        severity="high",
        category="llm",
    ),
    dict(
        name="OpenRouter API Key",
        pattern=re.compile(r"\bsk-or-v1-[A-Za-z0-9]{20,}\b"),
        severity="critical",
        category="llm",
    ),

    # ---- Cloud / infra (common in vibecoded backends-as-a-service) ----
    dict(
        name="AWS Access Key ID",
        pattern=re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        severity="critical",
        category="cloud",
    ),
    dict(
        name="Supabase Service Role Key (JWT)",
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        severity="high",
        category="cloud",
    ),
    dict(
        name="Firebase API Key",
        pattern=re.compile(r"\bAIzaSy[0-9A-Za-z_-]{33}\b"),
        severity="medium",
        category="cloud",
    ),
    dict(
        name="Generic Slack Token",
        pattern=re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        severity="high",
        category="cloud",
    ),

    # ---- Payments ----
    dict(
        name="Stripe Secret Key",
        pattern=re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b"),
        severity="critical",
        category="payment",
    ),
    dict(
        name="Stripe Restricted Key",
        pattern=re.compile(r"\brk_live_[A-Za-z0-9]{24,}\b"),
        severity="critical",
        category="payment",
    ),

    # ---- Generic catch-alls ----
    dict(
        name="Generic Bearer Token in Source",
        pattern=re.compile(r"Bearer\s+[A-Za-z0-9_\-\.=]{20,}"),
        severity="medium",
        category="generic",
    ),
    dict(
        name="Hardcoded 'apiKey' / 'api_key' Assignment",
        pattern=re.compile(
            r"""(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*["']([A-Za-z0-9_\-\.]{16,})["']"""
        ),
        severity="medium",
        category="generic",
    ),
]

# Providers whose keys, if exposed client-side, directly translate into
# an attacker being able to spend the app owner's money on LLM usage.
LLM_KEY_NAMES = {p["name"] for p in KEY_PATTERNS if p["category"] == "llm"}
