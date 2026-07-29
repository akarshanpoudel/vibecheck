import logging
from datetime import timedelta

from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone

from .decorators import scan_rate_limit
from .forms import ScanForm
from .models import Scan
from .tasks import start_scan

logger = logging.getLogger(__name__)

PENDING_TIMEOUT = timedelta(minutes=3)
MAX_HISTORY     = 10
DEDUP_WINDOW    = timedelta(seconds=60)   # don't re-scan the same URL within 60 s


def _recent_scan(target_url: str) -> Scan | None:
    """Return an existing pending/complete scan for this URL if one exists
    within DEDUP_WINDOW, so a double-click or network retry doesn't spin up
    two parallel workers against the same target."""
    cutoff = timezone.now() - DEDUP_WINDOW
    return (
        Scan.objects
        .filter(
            target_url=target_url,
            created_at__gte=cutoff,
            status__in=[Scan.STATUS_PENDING, Scan.STATUS_COMPLETE],
        )
        .order_by("-created_at")
        .first()
    )


def _push_history(request, slug: str) -> None:
    history = request.session.get("scan_history", [])
    history = [s for s in history if s != slug]
    history.insert(0, slug)
    request.session["scan_history"] = history[:MAX_HISTORY]


def _get_history(request) -> list[Scan]:
    slugs = request.session.get("scan_history", [])
    if not slugs:
        return []
    by_slug = {
        s.slug: s
        for s in Scan.objects.filter(slug__in=slugs).exclude(status=Scan.STATUS_PENDING)
    }
    return [by_slug[slug] for slug in slugs if slug in by_slug]


@scan_rate_limit
def index(request):
    form = ScanForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        target_url = form.cleaned_data["target_url"]

        # Deduplication — reuse a very recent scan rather than spawning a new worker
        existing = _recent_scan(target_url)
        if existing:
            logger.info("scan.deduped url=%s reusing_slug=%s", target_url, existing.slug)
            _push_history(request, existing.slug)
            return redirect(reverse("scanner:result", args=[existing.slug]))

        scan = Scan.objects.create(
            target_url=target_url,
            status=Scan.STATUS_PENDING,
            ok=True,
        )
        start_scan(scan)
        _push_history(request, scan.slug)
        logger.info("scan.started url=%s slug=%s", target_url, scan.slug)
        return redirect(reverse("scanner:result", args=[scan.slug]))

    scan_count = Scan.objects.filter(status=Scan.STATUS_COMPLETE).count()
    return render(request, "scanner/index.html", {
        "form":         form,
        "recent_scans": _get_history(request),
        "scan_count":   scan_count,
    })


def result(request, slug: str):
    scan = get_object_or_404(Scan, slug=slug)

    if scan.status == Scan.STATUS_PENDING:
        if timezone.now() - scan.created_at > PENDING_TIMEOUT:
            scan.status = Scan.STATUS_FAILED
            scan.ok     = False
            scan.error  = "Scan timed out — the worker may have been interrupted. Please try again."
            scan.save(update_fields=["status", "ok", "error"])
            logger.warning("scan.timeout slug=%s", slug)
        else:
            return render(request, "scanner/result.html", {"scan": scan})

    findings = scan.findings.all()
    is_clean  = scan.ok and findings.count() == 0

    if scan.ok:
        logger.info("scan.complete slug=%s findings=%d clean=%s", slug, findings.count(), is_clean)

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
        "is_clean": is_clean,
    })


def scan_status(request, slug: str):
    scan = get_object_or_404(Scan, slug=slug)
    return JsonResponse({"status": scan.status})


def clear_history(request):
    if request.method == "POST":
        request.session.pop("scan_history", None)
    return redirect(reverse("scanner:index"))


def health(request):
    return JsonResponse({"ok": True})


def api_result(request, slug: str):
    """
    GET /api/scan/<slug>/
    Machine-readable result — use this from CI pipelines:
      curl -s https://yoursite.com/api/scan/<slug>/ | jq .summary
    """
    scan = get_object_or_404(Scan, slug=slug)
    findings_data = [
        {
            "type":           f.finding_type,
            "title":          f.title,
            "severity":       f.severity,
            "confidence":     f.confidence,
            "evidence":       f.evidence,
            "location":       f.location,
            "recommendation": f.recommendation,
            "category":       f.category,
        }
        for f in scan.findings.all()
    ]
    return JsonResponse({
        "slug":             scan.slug,
        "target_url":       scan.target_url,
        "status":           scan.status,
        "ok":               scan.ok,
        "error":            scan.error or None,
        "scanned_at":       scan.created_at.isoformat(),
        "assets_scanned":   scan.assets_scanned,
        "endpoints_probed": scan.endpoints_probed,
        "findings":         findings_data,
        "summary": {
            "critical": sum(1 for f in findings_data if f["severity"] == "critical"),
            "high":     sum(1 for f in findings_data if f["severity"] == "high"),
            "medium":   sum(1 for f in findings_data if f["severity"] == "medium"),
            "total":    len(findings_data),
        },
    })