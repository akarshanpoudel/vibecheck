import secrets

from django.db import migrations, models


def _populate_slugs(apps, schema_editor):
    Scan = apps.get_model("scanner", "Scan")
    for scan in Scan.objects.filter(slug__isnull=True):
        while True:
            candidate = secrets.token_urlsafe(10)
            if not Scan.objects.filter(slug=candidate).exists():
                break
        scan.slug = candidate
        scan.save(update_fields=["slug"])


class Migration(migrations.Migration):

    dependencies = [("scanner", "0002_scan_status")]

    operations = [
        # Step 1: add nullable so existing rows don't violate NOT NULL
        migrations.AddField(
            model_name="scan",
            name="slug",
            field=models.CharField(max_length=20, null=True, blank=True),
        ),
        # Step 2: fill existing rows
        migrations.RunPython(_populate_slugs, migrations.RunPython.noop),
        # Step 3: tighten to unique + non-nullable
        migrations.AlterField(
            model_name="scan",
            name="slug",
            field=models.CharField(max_length=20, unique=True, db_index=True),
        ),
    ]