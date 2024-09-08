# Generated by Django 5.0.6 on 2024-09-07 11:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        (
            "licenseApplication",
            "0005_rename_local_government_newlicenseapplication_local_government_of_residence_and_more",
        ),
    ]

    operations = [
        migrations.AlterField(
            model_name="newlicenseapplication",
            name="facial_mark",
            field=models.CharField(default=1, max_length=255),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name="newlicenseapplication",
            name="height",
            field=models.DecimalField(decimal_places=2, default=1, max_digits=5),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name="newlicenseapplication",
            name="local_government_of_origin",
            field=models.CharField(default=1, max_length=100),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name="newlicenseapplication",
            name="nationality",
            field=models.CharField(default=1, max_length=100),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name="newlicenseapplication",
            name="next_of_kin_full_name",
            field=models.CharField(default=1, max_length=255),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name="newlicenseapplication",
            name="next_of_kin_phone_number",
            field=models.CharField(blank=True, default=1, max_length=15),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name="newlicenseapplication",
            name="state_of_origin",
            field=models.CharField(default=1, max_length=100),
            preserve_default=False,
        ),
    ]
