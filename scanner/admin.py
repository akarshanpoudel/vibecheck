import logging

from django.contrib import admin, messages
from django.contrib.admin import helpers
from django.db.models import Count
from django.template.response import TemplateResponse
from django.utils.html import format_html

from .models import Finding, Scan
from .tasks import start_scan

logger = logging.getLogger(__name__)


@admin.action(description="Re-run selected scans")
def rerun_scans(modeladmin, request, queryset):
    eligible = queryset.exclude(status=Scan.STATUS_PENDING)

    # First pass — show confirmation page
    if "confirm" not in request.POST:
        return TemplateResponse(
            request,
            "admin/scanner/rerun_confirm.html",
            {
                **modeladmin.admin_site.each_context(request),
                "title":               "Re-run scans",
                "scans":               eligible,
                "count":               eligible.count(),
                "queryset":            queryset,
                "action_checkbox_name": helpers.ACTION_CHECKBOX_NAME,
                "opts":                modeladmin.model._meta,
            },
        )

    # Second pass — confirmed, execute
    count = 0
    for scan in eligible:
        scan.findings.all().delete()
        scan.status = Scan.STATUS_PENDING
        scan.ok     = True
        scan.error  = ""
        scan.save(update_fields=["status", "ok", "error"])
        start_scan(scan)
        count += 1
        logger.info("admin.rerun scan_id=%d url=%s", scan.id, scan.target_url)

    modeladmin.message_user(request, f"Re-queued {count} scan(s).", messages.SUCCESS)


class FindingInline(admin.TabularInline):
    model           = Finding
    extra           = 0
    fields          = ("severity", "confidence", "title", "category", "location")
    readonly_fields = fields

    def has_add_permission(self, request, obj=None):
        return False


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display    = ("target_url", "status_badge", "finding_count", "created_at")
    list_filter     = ("status",)
    search_fields   = ("target_url",)
    readonly_fields = ("slug", "created_at", "status", "ok", "error",
                       "assets_scanned", "endpoints_probed")
    inlines         = (FindingInline,)
    actions         = (rerun_scans,)
    ordering        = ("-created_at",)
    list_per_page   = 50                   # ← item 7 (pagination)

    def get_queryset(self, request):
        return super().get_queryset(request).annotate(_finding_count=Count("findings"))

    @admin.display(description="Findings", ordering="_finding_count")
    def finding_count(self, obj):
        return obj._finding_count

    @admin.display(description="Status")
    def status_badge(self, obj):
        colours = {
            Scan.STATUS_COMPLETE: "#2ea870",
            Scan.STATUS_PENDING:  "#e8920a",
            Scan.STATUS_FAILED:   "#f03e3e",
        }
        return format_html(
            '<span style="color:{};font-weight:600">{}</span>',
            colours.get(obj.status, "#888"),
            obj.status,
        )


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display  = ("severity", "confidence", "title", "category", "scan")
    list_filter   = ("severity", "confidence", "category")
    search_fields = ("title", "scan__target_url")
    ordering      = ("severity",)

    @admin.display(description="Target URL")
    def scan_url(self, obj):
        return obj.scan.target_url