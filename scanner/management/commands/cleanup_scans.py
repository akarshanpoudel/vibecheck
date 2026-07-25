"""
python manage.py cleanup_scans [--max-age-days N] [--dry-run]

Designed to run as a cron job or Heroku scheduler task.

  --max-age-days N   Delete scans (and findings) older than N days.
                     Omit to keep all history.
  --dry-run          Report what would happen without writing anything.
"""
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from scanner.models import Scan

# Must match PENDING_TIMEOUT in views.py
STALE_AFTER_MINUTES = 5


class Command(BaseCommand):
    help = "Mark stale pending scans as failed; optionally prune old records."

    def add_arguments(self, parser):
        parser.add_argument(
            "--max-age-days",
            type=int,
            default=None,
            metavar="N",
            help="Delete scans older than N days (default: keep all)",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Print what would be done without making changes",
        )

    def handle(self, *args, **options):
        dry  = options["dry_run"]
        now  = timezone.now()
        tag  = "[dry-run] " if dry else ""

        # ---- 1. Mark stale pending scans as failed ------------------
        cutoff = now - timedelta(minutes=STALE_AFTER_MINUTES)
        stale  = Scan.objects.filter(status=Scan.STATUS_PENDING, created_at__lt=cutoff)
        count  = stale.count()
        if dry:
            self.stdout.write(f"{tag}Would mark {count} stale pending scan(s) as failed.")
        else:
            updated = stale.update(
                status=Scan.STATUS_FAILED,
                ok=False,
                error="Scan timed out — worker was interrupted (detected by cleanup_scans).",
            )
            self.stdout.write(self.style.SUCCESS(f"Marked {updated} stale pending scan(s) as failed."))

        # ---- 2. Prune old records ------------------------------------
        max_age = options["max_age_days"]
        if max_age is None:
            return

        prune_cutoff = now - timedelta(days=max_age)
        old          = Scan.objects.filter(created_at__lt=prune_cutoff)
        old_count    = old.count()
        if dry:
            self.stdout.write(f"{tag}Would delete {old_count} scan(s) older than {max_age} day(s).")
        else:
            old.delete()  # CASCADE removes findings too
            self.stdout.write(self.style.SUCCESS(
                f"Deleted {old_count} scan(s) older than {max_age} day(s)."
            ))