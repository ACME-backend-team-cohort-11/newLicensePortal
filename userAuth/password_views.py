from .views import BaseUserView
from .serializers import  PasswordResetSerializer
from .utils import logger, format_error_response, get_user_by_email, send_email
from .models import CustomUser
from .tokens import password_reset_token_generator

from drf_yasg.utils import swagger_auto_schema 
from drf_yasg import openapi

from rest_framework import generics, status
from rest_framework.response import Response

from django.utils.encoding import force_bytes, force_str
from django.http import HttpResponse
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.shortcuts import render
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string


class PasswordResetView(BaseUserView, generics.GenericAPIView):
    serializer_class = PasswordResetSerializer

    @swagger_auto_schema(
        operation_description="Request a password reset.",
        responses={
            200: openapi.Response("Password reset instructions have been sent to your email."),
            404: openapi.Response("Email not found.")
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        user = get_user_by_email(email)

        if user:
            self.send_password_reset_email(user.id, request)
            return Response({'message': 'Password reset instructions have been sent to your email.'}, status=status.HTTP_200_OK)
        else:
            logger.info(f"Password reset request for non-existent email: {email}")
            return Response(format_error_response(
                status_code=status.HTTP_404_NOT_FOUND,
                error_code="EMAIL_NOT_FOUND",
                message="The email address was not found.",
                details={"email": email}
            ), status=status.HTTP_404_NOT_FOUND)

    def send_password_reset_email(self, user_id, request):
        try:
            user = CustomUser.objects.get(id=user_id)
            token = password_reset_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            domain = get_current_site(request).domain
            reset_link = f'http://{domain}/api/v1/password-reset-confirm/{uid}/{token}/'

            email_body = render_to_string('email/password_reset_email.html', {
                'user': user,
                'reset_link': reset_link,
            })
            send_email('Password Reset', email_body, user.email)
        except Exception as e:
            logger.error(f"Error sending password reset email: {str(e)}", exc_info=True)

class PasswordResetConfirmView(BaseUserView):

    @swagger_auto_schema(
        operation_description="Render password reset form for a given token and user ID."
    )
    def get(self, request, uidb64, token, *args, **kwargs):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = CustomUser.get_user_by_id(uid)

            if user and password_reset_token_generator.check_token(user, token):
                context = {'uidb64': uidb64, 'token': token}
                return render(request, 'email/password_reset_form.html', context)
            else:
                return HttpResponse("Invalid password reset link.", status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error rendering password reset form: {str(e)}", exc_info=True)
            return HttpResponse("An error occurred.", status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        operation_description="Handle form submission for password reset.",
        responses={
            200: openapi.Response("Password reset successful."),
            400: openapi.Response("Invalid token or user.")
        }
    )
    def post(self, request, uidb64, token, *args, **kwargs):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = CustomUser.get_user_by_id(uid)

            if user and password_reset_token_generator.check_token(user, token):
                password = request.POST.get('password')
                if not password:
                    return render(request, 'email/password_reset_form.html', {
                        'uidb64': uidb64,
                        'token': token,
                        'error': "Password field cannot be empty."
                    })

                user.set_password(password)
                user.save()

                logger.info(f"Password reset successful for user: {user.email}")
                return render(request, "email/password_success.html", status=status.HTTP_200_OK)
            else:
                logger.warning(f"Invalid token or user for password reset. UID: {uid}")
                return HttpResponse("Invalid token or user.", status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error during password reset confirmation: {str(e)}", exc_info=True)
            return HttpResponse("An error occurred.", status=status.HTTP_500_INTERNAL_SERVER_ERROR)
