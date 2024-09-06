import logging
from django.conf import settings
from django.core.cache import cache
from django.core.mail import EmailMessage
from .models import CustomUser

logger = logging.getLogger(__name__)


# Utility functions
def format_error_response(status_code, error_code, message, details=None):
    return {
        "status": "error",
        "status_code": status_code,
        "error": {
            "code": error_code,
            "message": message,
            "details": details or {}
        }
    }

def get_user_by_email(email):
    user = cache.get(f"user_email_{email}")
    if not user:
        user = CustomUser.get_user_by_email(email)
        if user:
            cache.set(f"user_email_{email}", user)
    return user

def send_email(subject, body, to_email):
    try:
        email_message = EmailMessage(
            subject=subject,
            body=body,
            from_email=settings.EMAIL_HOST_USER,
            to=[to_email]
        )
        email_message.content_subtype = 'html'
        email_message.send()
        logger.info(f"Email sent to: {to_email}")
    except Exception as e:
        logger.error(f"Error sending email: {str(e)}", exc_info=True)
        raise