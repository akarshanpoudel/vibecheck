import re

KEY_PATTERNS = [
    # ---- LLM providers ------------------------------------------------
    {"name": "OpenAI API Key",
     "pattern": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
     "severity": "critical", "category": "llm", "confidence": "high"},

    {"name": "Anthropic API Key",
     "pattern": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
     "severity": "critical", "category": "llm", "confidence": "high"},

    {"name": "Google Gemini / Generic Google API Key",
     "pattern": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
     "severity": "critical", "category": "llm", "confidence": "medium"},

    {"name": "Cohere API Key",
     "pattern": re.compile(r"\bco-[A-Za-z0-9]{40,}\b"),
     "severity": "critical", "category": "llm", "confidence": "medium"},

    {"name": "Hugging Face Token",
     "pattern": re.compile(r"\bhf_[A-Za-z0-9]{34,}\b"),
     "severity": "critical", "category": "llm", "confidence": "high"},

    {"name": "Mistral API Key",
     "pattern": re.compile(r"\bmis-[A-Za-z0-9]{32,}\b"),
     "severity": "high", "category": "llm", "confidence": "high"},

    {"name": "Groq API Key",
     "pattern": re.compile(r"\bgsk_[A-Za-z0-9]{20,}\b"),
     "severity": "critical", "category": "llm", "confidence": "high"},

    {"name": "Perplexity API Key",
     "pattern": re.compile(r"\bpplx-[A-Za-z0-9]{32,}\b"),
     "severity": "critical", "category": "llm", "confidence": "high"},

    {"name": "Replicate API Token",
     "pattern": re.compile(r"\br8_[A-Za-z0-9]{32,}\b"),
     "severity": "critical", "category": "llm", "confidence": "high"},

    {"name": "OpenRouter API Key",
     "pattern": re.compile(r"\bsk-or-v1-[A-Za-z0-9]{20,}\b"),
     "severity": "critical", "category": "llm", "confidence": "high"},

    {"name": "xAI (Grok) API Key",
     "pattern": re.compile(r"\bxai-[A-Za-z0-9]{40,}\b"),
     "severity": "critical", "category": "llm", "confidence": "high"},

    {"name": "Fireworks AI API Key",
     "pattern": re.compile(r"\bfw_[A-Za-z0-9]{32,}\b"),
     "severity": "critical", "category": "llm", "confidence": "high"},

    {"name": "Tavily AI API Key",
     "pattern": re.compile(r"\btvly-[A-Za-z0-9]{32,}\b"),
     "severity": "high", "category": "llm", "confidence": "high"},

    {"name": "Cerebras API Key",
     "pattern": re.compile(r"\bcsk-[A-Za-z0-9]{32,}\b"),
     "severity": "critical", "category": "llm", "confidence": "high"},

    {"name": "ElevenLabs API Key",
     "pattern": re.compile(r"\b[a-f0-9]{32}\b(?=.{0,40}elevenlabs)", re.IGNORECASE),
     "severity": "high", "category": "llm", "confidence": "low"},

    # ---- Cloud / infra ------------------------------------------------
    {"name": "AWS Access Key ID",
     "pattern": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
     "severity": "critical", "category": "cloud", "confidence": "high"},

    {"name": "Supabase Service Role Key (JWT)",
     "pattern": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
     "context": re.compile(r"supabase|service[_-]?role", re.IGNORECASE),
     "context_window": 300,
     "severity": "high", "category": "cloud", "confidence": "medium"},

    {"name": "Firebase API Key",
     "pattern": re.compile(r"\bAIzaSy[0-9A-Za-z_-]{33}\b"),
     "severity": "medium", "category": "cloud", "confidence": "high"},

    {"name": "Slack Token",
     "pattern": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
     "severity": "high", "category": "cloud", "confidence": "high"},

    {"name": "GitHub Personal Access Token",
     "pattern": re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"),
     "severity": "critical", "category": "cloud", "confidence": "high"},

    {"name": "GitHub Fine-Grained PAT",
     "pattern": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
     "severity": "critical", "category": "cloud", "confidence": "high"},

    {"name": "Mapbox Public Token",
     "pattern": re.compile(r"\bpk\.eyJ1[A-Za-z0-9._-]{20,}\b"),
     "severity": "medium", "category": "cloud", "confidence": "high"},

    # ---- Payments & comms ---------------------------------------------
    {"name": "Stripe Secret Key",
     "pattern": re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b"),
     "severity": "critical", "category": "payment", "confidence": "high"},

    {"name": "Stripe Restricted Key",
     "pattern": re.compile(r"\brk_live_[A-Za-z0-9]{24,}\b"),
     "severity": "critical", "category": "payment", "confidence": "high"},

    {"name": "SendGrid API Key",
     "pattern": re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
     "severity": "high", "category": "payment", "confidence": "high"},

    {"name": "Resend API Key",
     "pattern": re.compile(r"\bre_[A-Za-z0-9_]{20,}\b"),
     "severity": "high", "category": "payment", "confidence": "medium"},

    {"name": "Twilio API Key",
     "pattern": re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
     "severity": "high", "category": "payment", "confidence": "medium"},

    # ---- Generic catch-alls (noisy — always low confidence) -----------
     {"name": "Bearer Token in Source",
      "pattern": re.compile(r"Bearer\s+[A-Za-z0-9_\-\.=]{20,}"),
      "context": re.compile(r"Authorization|[Hh]eaders|auth|fetch|axios|XMLHttpRequest", re.IGNORECASE),
      "context_window": 200,
      "severity": "medium", "category": "generic", "confidence": "low"},

     {"name": "Hardcoded API Key Assignment",
      "pattern": re.compile(
           r"""(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*["']([A-Za-z0-9_\-\.]{16,})["']"""
      ),
      "severity": "medium", "category": "generic", "confidence": "low"},
]

LLM_KEY_NAMES = {p["name"] for p in KEY_PATTERNS if p["category"] == "llm"}