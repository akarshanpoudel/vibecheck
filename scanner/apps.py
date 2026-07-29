import logging

from django.apps import AppConfig
from django.conf import settings


class ScannerConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "scanner"

    def ready(self) -> None:
        logger = logging.getLogger(__name__)

        if not settings.DEBUG:
            backend = settings.CACHES.get("default", {}).get("BACKEND", "")
            if "locmem" in backend.lower():
                logger.warning(
                    "rate_limit.backend=locmem "
                    "LocMemCache is per-process. With multiple gunicorn workers "
                    "each IP gets SCAN_RATE_LIMIT * workers scans/hour instead of "
                    "SCAN_RATE_LIMIT. Set REDIS_URL in production to fix this."
                )