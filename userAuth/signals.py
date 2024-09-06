from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import CustomUser, Profile
from adminUserApp.models import AdminProfile
from licenseApplication.models import NewLicenseApplication  

@receiver(post_save, sender=CustomUser)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)
    else:
        instance.profile.save()



@receiver(post_save, sender=NewLicenseApplication)
def update_profile_from_application(sender, instance, created, **kwargs):
    if created:
        profile, _ = Profile.objects.get_or_create(user=instance.user)
        profile.first_name = instance.first_name 
        profile.last_name = instance.last_name
        profile.date_of_birth = instance.date_of_birth
        profile.phone_number = instance.phone_number
        profile.address = instance.street_address
        profile.gender = instance.gender
        profile.mother_maiden_name = instance.mother_maiden_name
        profile.NIN = instance.NIN
        profile.passport_photo = instance.passport_photo
        profile.save()
        


@receiver(post_save, sender=CustomUser)
def create_or_update_admin_profile(sender, instance, created, **kwargs):
    if created and instance.is_staff:
        AdminProfile.objects.create(user=instance)
    elif instance.is_staff:
        instance.adminprofile.save()