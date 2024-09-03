# # application/signals.py
# from django.db.models.signals import post_save
# from django.dispatch import receiver
# from licenseApplication.models import NewLicenseApplication
# from userAuth.models import Profile

# @receiver(post_save, sender=NewLicenseApplication)
# def create_or_update_profile(sender, instance, created, **kwargs):
#     """Create or update a user profile when a new license application is saved."""
#     profile_data = {
#         'phone_number': instance.phone_number,
#         'address': instance.street_address,
#         'date_of_birth': instance.date_of_birth,
#         'gender': instance.gender,
#         'mother_maiden_name': instance.mother_maiden_name,
#         'NIN': instance.NIN,
#         'passport_photo': instance.passport_photo,
#     }
#     Profile.objects.update_or_create(user=instance.user, defaults=profile_data)
