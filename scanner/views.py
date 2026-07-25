import threading
from datetime import timedelta

from django.db import connection
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone

from .decorators import scan_rate_limit
from .forms import ScanForm
from .models import Finding, Scan
from .services.recommendations import (
    OPEN_ENDPOINT_RECOMMENDATION,
    PERMISSIVE_CORS_RECOMMENDATION,
    recommendation_for_category,
)
from .services.scanner import run_scan

SEVERITY_ORDER  = {"critical": 0, "high": 1, "medium": 2, "low": 3}
PENDING_TIMEOUT = timedelta(minutes=3)


def _run_scan_bg(scan_id: int, target_url: str) -> None:
    """Runs in a daemon thread. Persists results when done."""
    try:
        result = run_scan(target_url)

        scan = Scan.objects.get(id=scan_id)
        scan.ok               = result.ok
        scan.error            = result.error or ""
        scan.assets_scanned   = result.assets_scanned
        scan.endpoints_probed = result.endpoints_probed
        scan.status           = Scan.STATUS_COMPLETE
        scan.save()

        for f in sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9)):
            if f.finding_type == "open_endpoint":
                rec = OPEN_ENDPOINT_RECOMMENDATION
            elif f.finding_type == "cors":
                rec = PERMISSIVE_CORS_RECOMMENDATION
            else:
                rec = recommendation_for_category(f.category)

            Finding.objects.create(
                scan=scan,
                finding_type=f.finding_type,
                title=f.title,
                severity=f.severity,
                evidence=f.evidence,
                location=f.location,
                recommendation=rec,
                category=f.category,
            )
    except Exception as exc:  # noqa: BLE001
        Scan.objects.filter(id=scan_id).update(
            status=Scan.STATUS_FAILED,
            ok=False,
            error=str(exc),
        )
    finally:
        connection.close()


@scan_rate_limit
def index(request):
    form = ScanForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        target_url = form.cleaned_data["target_url"]
        scan = Scan.objects.create(
            target_url=target_url,
            status=Scan.STATUS_PENDING,
            ok=True,
        )
        t = threading.Thread(target=_run_scan_bg, args=(scan.id, target_url), daemon=True)
        t.start()
        return redirect(reverse("scanner:result", args=[scan.id]))

    recent_scans = Scan.objects.exclude(status=Scan.STATUS_PENDING)[:5]
    return render(request, "scanner/index.html", {"form": form, "recent_scans": recent_scans})


def result(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)

    if scan.status == Scan.STATUS_PENDING:
        # Stale-pending guard: if the worker was killed mid-scan the record
        # stays pending forever. After PENDING_TIMEOUT, fail it gracefully.
        if timezone.now() - scan.created_at > PENDING_TIMEOUT:
            scan.status = Scan.STATUS_FAILED
            scan.ok     = False
            scan.error  = (
                "The scan timed out — the worker may have been interrupted. "
                "Please try again."
            )
            scan.save(update_fields=["status", "ok", "error"])
            # Fall through to render the error state below.
        else:
            return render(request, "scanner/result.html", {"scan": scan})

    findings = scan.findings.all()

    return render(
        request,
        "scanner/result.html",
        {
            "scan": scan,
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
        },
    )


def scan_status(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)
    return JsonResponse({"status": scan.status})