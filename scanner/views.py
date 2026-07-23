import threading

from django.db import connection
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse

from .decorators import scan_rate_limit
from .forms import ScanForm
from .models import Finding, Scan
from .services.recommendations import (
    OPEN_ENDPOINT_RECOMMENDATION,
    PERMISSIVE_CORS_RECOMMENDATION,
    recommendation_for_category,
)
from .services.scanner import run_scan

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _run_scan_bg(scan_id: int, target_url: str) -> None:
    """Executed in a daemon thread. Runs the scan, persists results."""
    try:
        result = run_scan(target_url)

        scan = Scan.objects.get(id=scan_id)
        scan.ok              = result.ok
        scan.error           = result.error or ""
        scan.assets_scanned  = result.assets_scanned
        scan.endpoints_probed = result.endpoints_probed
        scan.status          = Scan.STATUS_COMPLETE
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
        # Each thread gets its own DB connection; always release it.
        connection.close()


@scan_rate_limit
def index(request):
    form = ScanForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        target_url = form.cleaned_data["target_url"]

        # Create a pending record immediately so the user gets a result
        # page straight away rather than waiting through the full scan.
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

    # Pending: return early — template handles the polling UI.
    if scan.status == Scan.STATUS_PENDING:
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
    """Lightweight JSON endpoint polled by the pending result page."""
    scan = get_object_or_404(Scan, id=scan_id)
    return JsonResponse({"status": scan.status})