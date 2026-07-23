"""
Maps finding categories/types to human-readable, actionable recommendations.
"""

LLM_KEY_RECOMMENDATION = (
    "This looks like a live LLM provider API key shipped in client-side code. "
    "Anyone viewing your page source can copy it and make requests billed to "
    "your account. Fix: (1) Rotate/revoke this key immediately in the "
    "provider's dashboard, (2) move all LLM calls to a backend endpoint "
    "(e.g. a Django view) that holds the key in an environment variable / "
    "secrets manager, (3) have the frontend call your backend instead of "
    "the LLM API directly, (4) add per-user rate limiting and, ideally, "
    "authentication on that backend endpoint so the proxy itself can't be "
    "abused for free."
)

CLOUD_KEY_RECOMMENDATION = (
    "This looks like a cloud/service credential exposed in client-side code. "
    "Rotate it immediately, then move it server-side (environment variable, "
    "not committed to source control) and scope it with least-privilege "
    "permissions / row-level security rules rather than a broad key."
)

PAYMENT_KEY_RECOMMENDATION = (
    "This looks like a live payment provider secret key. This is severe — "
    "it can be used to move money or access customer payment data. Revoke "
    "and rotate it immediately, and only ever use the publishable/public "
    "key on the client. Secret keys belong only on your backend."
)

GENERIC_RECOMMENDATION = (
    "This looks like a hardcoded secret or token in client-visible code. "
    "Treat it as compromised: rotate it, move it to a server-side "
    "environment variable, and route the relevant calls through your "
    "backend instead of exposing the credential to the browser."
)

CATEGORY_RECOMMENDATIONS = {
    "llm": LLM_KEY_RECOMMENDATION,
    "cloud": CLOUD_KEY_RECOMMENDATION,
    "payment": PAYMENT_KEY_RECOMMENDATION,
    "generic": GENERIC_RECOMMENDATION,
}

OPEN_ENDPOINT_RECOMMENDATION = (
    "This endpoint responded without requiring any authentication. If it "
    "proxies to an LLM provider or touches sensitive data, anyone can call "
    "it directly and run up usage costs or pull data. Fix: require an API "
    "key / session auth on the backend, add rate limiting per user/IP, and "
    "avoid trusting any 'secret' passed from the client."
)

PERMISSIVE_CORS_RECOMMENDATION = (
    "This endpoint returns 'Access-Control-Allow-Origin: *' (or reflects "
    "arbitrary origins), meaning any website can call it from a user's "
    "browser using that user's cookies/session if credentials are allowed. "
    "Fix: restrict Access-Control-Allow-Origin to your known frontend "
    "origin(s), and avoid combining wildcard origins with "
    "Access-Control-Allow-Credentials: true."
)


def recommendation_for_category(category: str) -> str:
    return CATEGORY_RECOMMENDATIONS.get(category, GENERIC_RECOMMENDATION)
