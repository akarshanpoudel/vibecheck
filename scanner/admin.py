from django.contrib import admin
from .models import Scan, Finding


class FindingInline(admin.TabularInline):
    model = Finding
    extra = 0


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ("target_url", "created_at", "ok")
    inlines = [FindingInline]


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ("title", "severity", "scan")
