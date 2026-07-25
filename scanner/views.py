from datetime import timedelta

from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone

from .decorators import scan_rate_limit
from .forms import ScanForm
from .models import Scan
from .tasks import start_scan

PENDING_TIMEOUT = timedelta(minutes=3)
MAX_HISTORY     = 10


def _push_history(request, slug: str) -> None:
    """Add a slug to the front of this visitor's session history."""
    history = request.session.get("scan_history", [])
    history = [s for s in history if s != slug]  # remove if already present (re-scan)
    history.insert(0, slug)
    request.session["scan_history"] = history[:MAX_HISTORY]


def _get_history(request) -> list[Scan]:
    """Return this visitor's scans in session order, completed only."""
    slugs = request.session.get("scan_history", [])
    if not slugs:
        return []
    by_slug = {
        s.slug: s
        for s in Scan.objects.filter(
            slug__in=slugs
        ).exclude(status=Scan.STATUS_PENDING)
    }
    # Preserve the session order (most recent first)
    return [by_slug[slug] for slug in slugs if slug in by_slug]


@scan_rate_limit
def index(request):
    form = ScanForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        scan = Scan.objects.create(
            target_url=form.cleaned_data["target_url"],
            status=Scan.STATUS_PENDING,
            ok=True,
        )
        start_scan(scan)
        _push_history(request, scan.slug)
        return redirect(reverse("scanner:result", args=[scan.slug]))

    return render(request, "scanner/index.html", {
        "form":         form,
        "recent_scans": _get_history(request),
    })


def result(request, slug: str):
    scan = get_object_or_404(Scan, slug=slug)

    if scan.status == Scan.STATUS_PENDING:
        if timezone.now() - scan.created_at > PENDING_TIMEOUT:
            scan.status = Scan.STATUS_FAILED
            scan.ok     = False
            scan.error  = "Scan timed out — the worker may have been interrupted. Please try again."
            scan.save(update_fields=["status", "ok", "error"])
        else:
            return render(request, "scanner/result.html", {"scan": scan})

    findings = scan.findings.all()

    return render(request, "scanner/result.html", {
        "scan":                  scan,
        "llm_findings":          [f for f in findings if f.category == "llm"],
        "other_secret_findings": [f for f in findings if f.finding_type == "secret" and f.category != "llm"],
        "endpoint_findings":     [f for f in findings if f.finding_type == "open_endpoint"],
        "cors_findings":         [f for f in findings if f.finding_type == "cors"],
        "counts": {
            "critical": findings.filter(severity="critical").count(),
            "high":     findings.filter(severity="high").count(),
            "medium":   findings.filter(severity="medium").count(),
        },
        "is_clean": scan.ok and findings.count() == 0,
    })


def scan_status(request, slug: str):
    scan = get_object_or_404(Scan, slug=slug)
    return JsonResponse({"status": scan.status})


def clear_history(request):
    """POST-only. Wipes this visitor's scan history from their session."""
    if request.method == "POST":
        request.session.pop("scan_history", None)
    return redirect(reverse("scanner:index"))