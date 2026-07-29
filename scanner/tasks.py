"""
Background scanning task.
Imported by views.py and admin.py to avoid duplication and circular imports.
"""
import logging
import threading

from django.db import connection

from .models import Finding, Scan
from .services.recommendations import (
    OPEN_ENDPOINT_RECOMMENDATION,
    PERMISSIVE_CORS_RECOMMENDATION,
    recommendation_for_category,
)
from .services.scanner import run_scan

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def run_scan_bg(scan_id: int, target_url: str) -> None:
    logger.info("task.start scan_id=%d url=%s", scan_id, target_url)
    try:
        result = run_scan(target_url)

        scan = Scan.objects.get(id=scan_id)
        scan.ok               = result.ok
        scan.error            = result.error or ""
        scan.assets_scanned   = result.assets_scanned
        scan.endpoints_probed = result.endpoints_probed
        scan.status           = Scan.STATUS_COMPLETE
        scan.save()

        findings_sorted = sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
        for f in findings_sorted:
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
                confidence=f.confidence,        # ← new
                evidence=f.evidence,
                location=f.location,
                recommendation=rec,
                category=f.category,
            )

        logger.info(
            "task.complete scan_id=%d ok=%s findings=%d assets=%d",
            scan_id, result.ok, len(result.findings), len(result.assets_scanned),
        )

    except Exception as exc:
        logger.exception("task.error scan_id=%d url=%s", scan_id, target_url)
        Scan.objects.filter(id=scan_id).update(
            status=Scan.STATUS_FAILED,
            ok=False,
            error=str(exc),
        )
    finally:
        # Each thread gets its own DB connection — always release it.
        connection.close()


def start_scan(scan: Scan) -> None:
    """Spin up a daemon thread for a pending Scan record."""
    t = threading.Thread(target=run_scan_bg, args=(scan.id, scan.target_url), daemon=True)
    t.start()