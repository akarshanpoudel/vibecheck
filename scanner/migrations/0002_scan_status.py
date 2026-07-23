from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scanner", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="scan",
            name="status",
            field=models.CharField(default="complete", max_length=20),
        ),
    ]