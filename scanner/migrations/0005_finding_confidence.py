from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = (("scanner", "0004_alter_scan_slug"),)

    operations = (
        migrations.AddField(
            model_name="finding",
            name="confidence",
            field=models.CharField(
                choices=[("high", "High"), ("medium", "Medium"), ("low", "Low")],
                default="medium",
                max_length=10,
            ),
        ),
    )