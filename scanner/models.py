from django.db import models


class Scan(models.Model):
    target_url = models.URLField(max_length=2000)
    created_at = models.DateTimeField(auto_now_add=True)
    ok = models.BooleanField(default=True)
    error = models.TextField(blank=True, default="")
    assets_scanned = models.JSONField(default=list, blank=True)
    endpoints_probed = models.JSONField(default=list, blank=True)

    def __str__(self):
        return f"Scan({self.target_url})"

    class Meta:
        ordering = ["-created_at"]


class Finding(models.Model):
    SEVERITY_CHOICES = [
        ("critical", "Critical"),
        ("high", "High"),
        ("medium", "Medium"),
        ("low", "Low"),
    ]

    scan = models.ForeignKey(Scan, related_name="findings", on_delete=models.CASCADE)
    finding_type = models.CharField(max_length=50)
    title = models.CharField(max_length=255)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    evidence = models.TextField()
    location = models.CharField(max_length=2000)
    recommendation = models.TextField()
    category = models.CharField(max_length=50, default="generic")

    class Meta:
        ordering = ["severity"]

    def __str__(self):
        return f"{self.severity.upper()}: {self.title}"
