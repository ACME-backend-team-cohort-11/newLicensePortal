# from celery import shared_task
# from django.core.mail import EmailMessage
# from django.template.loader import render_to_string
# from django.conf import settings
# from .tokens import password_reset_token_generator
# from django.utils.http import urlsafe_base64_encode
# from django.utils.encoding import force_bytes
# import logging

# logger = logging.getLogger('celery')


# @shared_task
# def send_verification_email(email, verification_link):
#     email_subject = 'Activate Your Account'
#     message = render_to_string('activate.html', {'verification_link': verification_link})
    
#     email_message = EmailMessage(
#         email_subject,
#         message,
#         settings.EMAIL_HOST_USER,
#         [email]
#     )
#     email_message.content_subtype = 'html'

#     try:
#         email_message.send()
#         logger.info(f"Verification email sent from {settings.EMAIL_HOST_USER} to {email}.")
#     except Exception as e:
#         logger.error(f"Failed to send verification email from {settings.EMAIL_HOST_USER} to {email}. Error: {str(e)}")


# @shared_task
# def send_password_reset_email_task(user_id):
#     from .models import CustomUser
#     user = CustomUser.objects.get(id=user_id)
    
#     token = password_reset_token_generator.make_token(user)
#     uid = urlsafe_base64_encode(force_bytes(user.pk))
#     reset_link = f'http://127.0.0.1:8000/api/v1/password-reset-confirm/{uid}/{token}/'

#     email_subject = 'Password Reset'
#     message = render_to_string('password_reset_email.html', {'user': user, 'reset_link': reset_link})

#     email_message = EmailMessage(
#         email_subject,
#         message,
#         settings.EMAIL_HOST_USER,
#         [user.email]
#     )
#     email_message.content_subtype = 'html'

#     try:
#         email_message.send()
#         logger.info(f"Password reset email sent from {settings.EMAIL_HOST_USER} to {user.email}.")
#     except Exception as e:
#         logger.error(f"Failed to send password reset email from {settings.EMAIL_HOST_USER} to {user.email}. Error: {str(e)}")
