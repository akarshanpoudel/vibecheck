from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse

from .forms import ScanForm
from .models import Scan, Finding
from .services.scanner import run_scan
from .services.recommendations import recommendation_for_category, OPEN_ENDPOINT_RECOMMENDATION, \
    PERMISSIVE_CORS_RECOMMENDATION

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _recommendation_for(finding) -> str:
    if finding.finding_type == "open_endpoint":
        return OPEN_ENDPOINT_RECOMMENDATION
    if finding.finding_type == "cors":
        return PERMISSIVE_CORS_RECOMMENDATION
    return recommendation_for_category(finding.category)


def index(request):
    form = ScanForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        target_url = form.cleaned_data["target_url"]
        result = run_scan(target_url)

        scan = Scan.objects.create(
            target_url=result.target_url,
            ok=result.ok,
            error=result.error or "",
            assets_scanned=result.assets_scanned,
            endpoints_probed=result.endpoints_probed,
        )
        findings_sorted = sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
        for f in findings_sorted:
            Finding.objects.create(
                scan=scan,
                finding_type=f.finding_type,
                title=f.title,
                severity=f.severity,
                evidence=f.evidence,
                location=f.location,
                recommendation=(
                    OPEN_ENDPOINT_RECOMMENDATION if f.finding_type == "open_endpoint"
                    else PERMISSIVE_CORS_RECOMMENDATION if f.finding_type == "cors"
                    else recommendation_for_category(f.category)
                ),
                category=f.category,
            )
        return redirect(reverse("scanner:result", args=[scan.id]))

    recent_scans = Scan.objects.all()[:5]
    return render(request, "scanner/index.html", {"form": form, "recent_scans": recent_scans})


def result(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)
    findings = scan.findings.all()

    llm_findings = [f for f in findings if f.category == "llm"]
    other_secret_findings = [f for f in findings if f.finding_type == "secret" and f.category != "llm"]
    endpoint_findings = [f for f in findings if f.finding_type == "open_endpoint"]
    cors_findings = [f for f in findings if f.finding_type == "cors"]

    counts = {
        "critical": findings.filter(severity="critical").count(),
        "high": findings.filter(severity="high").count(),
        "medium": findings.filter(severity="medium").count(),
    }

    is_clean = scan.ok and findings.count() == 0

    return render(
        request,
        "scanner/result.html",
        {
            "scan": scan,
            "llm_findings": llm_findings,
            "other_secret_findings": other_secret_findings,
            "endpoint_findings": endpoint_findings,
            "cors_findings": cors_findings,
            "counts": counts,
            "is_clean": is_clean,
        },
    )
