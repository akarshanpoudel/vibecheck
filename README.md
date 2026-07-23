# VibeCheck

A Django app that checks a "vibecoded" web app (Lovable / Bolt / v0 / Replit /
Cursor-generated, etc.) for **exposed API keys, unauthenticated endpoints,
and CORS misconfigurations** — with a focus on LLM provider keys, since
that's the most common and most expensive leak in AI-generated frontends.

## What it actually does

Given a URL, VibeCheck:

1. Fetches the page's HTML.
2. Follows every `<script src="...">` on that page and fetches those JS
   bundles too (capped at 12 assets).
3. Regex-scans all of that text against a pattern library covering OpenAI,
   Anthropic, Gemini, Groq, Mistral, Cohere, Hugging Face, Replicate,
   OpenRouter, Perplexity, ElevenLabs, plus common cloud/payment keys
   (AWS, Stripe, Supabase, Firebase, Slack) and generic `apiKey: "..."`
   patterns.
4. Looks inside the JS for `fetch(...)` / `axios(...)` calls referencing
   API paths on the **same host**, and sends one safe `GET` to each
   (capped at 8) to see if it responds without any auth challenge.
5. Checks `Access-Control-Allow-Origin` / `Access-Control-Allow-Credentials`
   on the page and on every probed endpoint.
6. Shows every finding with severity, redacted evidence, and a concrete
   fix — not just "this is bad."

## What it deliberately does NOT do

- No brute-forcing, path fuzzing, or scanning of third-party domains
  (CDNs, analytics, fonts) — only your own host.
- No login, no auth bypass attempts, nothing beyond a plain GET.
- It only sees what a normal visitor's browser already receives. Secrets
  kept properly on your backend are invisible to it (that's the point).
- It is **not** a full security audit — treat a "clean" result as "nothing
  obvious in the client-visible surface," not "certified secure."

## Setup

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

python manage.py migrate
python manage.py runserver
```

Then open http://127.0.0.1:8000/ and paste a URL to scan.

## Project layout

```
vibecheck/
  vibecheck/            # Django project settings/urls
  scanner/
    models.py           # Scan, Finding
    forms.py            # ScanForm
    views.py            # index (form + run scan), result (report page)
    services/
      patterns.py        # regex library for keys/secrets
      recommendations.py # finding -> fix-it text
      scanner.py          # fetch/crawl/probe/scan orchestration
    templates/scanner/   # index.html, result.html, base.html
    static/scanner/style.css
```

## Extending it

- **Add a key pattern**: add an entry to `KEY_PATTERNS` in
  `scanner/services/patterns.py` — `name`, `pattern` (compiled regex),
  `severity`, `category`.
- **Add a recommendation**: extend `CATEGORY_RECOMMENDATIONS` in
  `scanner/services/recommendations.py`.
- **Run scans async**: for production, move `run_scan()` into a Celery
  task instead of calling it synchronously inside the view, so slow
  targets don't block a request/worker.
- **Rate limit / abuse prevention**: since this hits arbitrary URLs on
  the internet, add throttling (e.g. `django-ratelimit`) on the `index`
  view before deploying publicly.

## Known limitations to keep in mind

- Minified/obfuscated JS or secrets fetched dynamically at runtime (e.g.
  pulled from another endpoint after page load) can be missed.
- Endpoint discovery only looks at paths literally referenced in JS
  source — it won't find undocumented routes.
- Regex-based detection can produce occasional false positives (e.g. a
  long random-looking string that isn't actually a live key) — evidence
  is shown so you can verify each finding.
