from django.db import models
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator, EmailValidator
from django.utils.dateparse import parse_date



class LicenseApplication(models.Model):
    """Base model representing an application for a license."""

    NEW = 'new'
    RENEWAL = 'renewal'
    REISSUE = 'reissue'

    APPLICATION_TYPES = [
        (NEW, 'New License'),
        (RENEWAL, 'License Renewal'),
        (REISSUE, 'License Reissue'),
    ]

    PENDING = 'pending'
    APPROVED = 'approved'
    REJECTED = 'rejected'

    APPLICATION_STATUSES = [
        (PENDING, 'Pending'),
        (APPROVED, 'Approved'),
        (REJECTED, 'Rejected'),
    ]
    VEHICLE_TYPE_CHOICES = [
    ('A', 'Motorcycle'),
    ('B', 'Light Vehicle'),
    ('C', 'Light Commercial Vehicle'),
    ('D', 'Medium Vehicle'),
    ('E', 'Heavy Vehicle'),
    ('F', 'Agricultural Vehicles'),
    ('G', 'Articulated Vehicles'),
    ('H', 'Construction Vehicles'),
    ('I', 'Special Vehicles for Physically Handicapped Persons'),
    ]

    VALIDITY_YEAR_CHOICES = [
        (3, '3 Years'),
        (5, '5 Years'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    application_type = models.CharField(max_length=10, choices=APPLICATION_TYPES)
    vehicle_type = models.CharField(max_length=2, choices=VEHICLE_TYPE_CHOICES)
    validity_year = models.IntegerField(choices=VALIDITY_YEAR_CHOICES)
    status = models.CharField(max_length=10, choices=APPLICATION_STATUSES, default=PENDING)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.email} - {self.get_application_type_display()}"

    def clean(self):
        """Ensure application_type is valid."""
        if self.application_type not in dict(self.APPLICATION_TYPES):
            raise ValidationError(f"Invalid application type: {self.application_type}")

        super().clean()

    def save(self, *args, **kwargs):
        """Override save method to create an audit entry when the status changes."""
        self.full_clean()  # Ensures that the clean method is called before saving
        if self.pk is not None:
            old_status = LicenseApplication.objects.get(pk=self.pk).status
            if old_status != self.status:
                ApplicationAudit.objects.create(
                    application=self,
                    old_status=old_status,
                    new_status=self.status,
                    changed_by=self.user
                )
        super().save(*args, **kwargs)





class NewLicenseApplication(LicenseApplication):
    """Represents a new license application."""

    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    middle_name = models.CharField(max_length=50)
    gender = models.CharField(max_length=10, choices=[('male', 'Male'), ('female', 'Female')])
    date_of_birth = models.DateField()
    mother_maiden_name = models.CharField(max_length=100)
    NIN = models.CharField(
        max_length=20,
        unique=True,
        validators=[
            RegexValidator(
                regex=r'^\d{11}$',
                message='NIN must be exactly 11 digits.'
            )
        ]
    )
    passport_photo = models.ImageField(upload_to='passport_photos/', blank= False , null = False)

    # Contact Information
    phone_number = models.CharField(max_length=15)
    email = models.EmailField(
        max_length=254,
        validators=[EmailValidator(message='Enter a valid email address.')]
    )
    street_address = models.CharField(max_length=255)
    local_government_of_residence = models.CharField(max_length=100)
    state_of_residence = models.CharField(max_length=100)


    height = models.DecimalField(max_digits=5, decimal_places=2)  # Example: 175.5 (in cm)
    blood_group = models.CharField(
        max_length=3,
        choices=[
            ('A+', 'A+'), ('A-', 'A-'),
            ('B+', 'B+'), ('B-', 'B-'),
            ('AB+', 'AB+'), ('AB-', 'AB-'),
            ('O+', 'O+'), ('O-', 'O-')
        ]
    )
    local_government_of_origin = models.CharField(max_length=100)
    state_of_origin = models.CharField(max_length=100)
    nationality = models.CharField(max_length=100 )

    facial_mark = models.CharField(max_length=255)
    require_glasses = models.BooleanField(default=False)

    next_of_kin_phone_number = models.CharField(max_length=15)
    next_of_kin_full_name = models.CharField(max_length=255)



    class Meta:
        verbose_name = 'New License Application'
        verbose_name_plural = 'New License Applications'

    def clean(self):
        super().clean()  # Call the clean method of the parent class if it exists

        # Custom validation for date format
        if not isinstance(self.date_of_birth, str) and not parse_date(str(self.date_of_birth)):
            raise ValidationError({
                'date_of_birth': 'Date of Birth must be a valid date in the format YYYY-MM-DD.'
            })

        # Ensure NIN is exactly 11 digits
        if len(self.NIN) != 11 or not self.NIN.isdigit():
            raise ValidationError({
                'NIN': 'NIN must be exactly 11 digits.'
            })

    def save(self, *args, **kwargs):
        self.full_clean()  # This will call the clean method to validate before saving
        super().save(*args, **kwargs)


class RenewalLicenseApplication(LicenseApplication):
    """Represents a license renewal application."""

    email = models.EmailField(validators=[EmailValidator(message='Enter a valid email address.')])
    license_id = models.CharField(max_length=20)

    class Meta:
        verbose_name = 'License Renewal Application'
        verbose_name_plural = 'License Renewal Applications'

class ReissueLicenseApplication(LicenseApplication):
    """Represents a license reissue application."""

    email = models.EmailField(validators=[EmailValidator(message='Enter a valid email address.')])
    license_id = models.CharField(max_length=20)
    affidavit = models.FileField(upload_to='affidavits/')  # one filed needed
    police_report = models.FileField(upload_to='police_reports/')

    class Meta:
        verbose_name = 'License Reissue Application'
        verbose_name_plural = 'License Reissue Applications'

class ApplicationAudit(models.Model):
    """Tracks changes in the application status and other significant events."""

    application = models.ForeignKey(LicenseApplication, on_delete=models.CASCADE, related_name='audits')
    old_status = models.CharField(max_length=10, choices=LicenseApplication.APPLICATION_STATUSES)
    new_status = models.CharField(max_length=10, choices=LicenseApplication.APPLICATION_STATUSES)
    changed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    notes = models.TextField(blank=True, null=True)  # Optional notes for the audit trail

    def __str__(self):
        return f"Audit for {self.application} from {self.old_status} to {self.new_status} on {self.timestamp}"
