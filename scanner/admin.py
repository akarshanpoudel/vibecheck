import threading

from django.contrib import admin
from django.db.models import Count
from django.utils.html import format_html

from .models import Finding, Scan
from .tasks import start_scan


# ---- Actions --------------------------------------------------------

@admin.action(description="Re-run selected scans")
def rerun_scans(modeladmin, request, queryset):
    # Skip anything already in-flight.
    eligible = queryset.exclude(status=Scan.STATUS_PENDING)
    count = 0
    for scan in eligible:
        scan.findings.all().delete()
        scan.status = Scan.STATUS_PENDING
        scan.ok     = True
        scan.error  = ""
        scan.save(update_fields=["status", "ok", "error"])
        start_scan(scan)
        count += 1
    modeladmin.message_user(request, f"Re-queued {count} scan(s).")


# ---- ModelAdmins ----------------------------------------------------

class FindingInline(admin.TabularInline):
    model  = Finding
    extra  = 0
    fields = ("severity", "title", "category", "location")
    readonly_fields = fields

    def has_add_permission(self, request, obj=None):
        return False


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display   = ("target_url", "status_badge", "finding_count", "created_at")
    list_filter    = ("status",)
    search_fields  = ("target_url",)
    readonly_fields = ("slug", "created_at", "status", "ok", "error",
                       "assets_scanned", "endpoints_probed")
    inlines        = [FindingInline]
    actions        = [rerun_scans]
    ordering       = ("-created_at",)

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
        colour = colours.get(obj.status, "#888")
        return format_html(
            '<span style="color:{};font-weight:600">{}</span>',
            colour,
            obj.status,
        )


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display  = ("severity", "title", "category", "scan_url", "scan")
    list_filter   = ("severity", "category")
    search_fields = ("title", "scan__target_url")
    ordering      = ("severity",)

    @admin.display(description="Target URL")
    def scan_url(self, obj):
        return obj.scan.target_url