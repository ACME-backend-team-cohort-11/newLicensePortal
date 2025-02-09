# Generated by Django 5.0.6 on 2024-09-07 11:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('licenseApplication', '0004_newlicenseapplication_blood_group_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='newlicenseapplication',
            old_name='local_government',
            new_name='local_government_of_residence',
        ),
        migrations.RenameField(
            model_name='newlicenseapplication',
            old_name='state',
            new_name='state_of_residence',
        ),
        migrations.AddField(
            model_name='newlicenseapplication',
            name='local_government_of_origin',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='newlicenseapplication',
            name='next_of_kin_full_name',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='newlicenseapplication',
            name='state_of_origin',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
    ]
