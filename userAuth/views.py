import logging
from django.shortcuts import render
from django.conf import settings
from django.core.cache import cache
from django.core.mail import EmailMessage
from django.utils.encoding import force_bytes, force_str
from django.contrib.sites.shortcuts import get_current_site 
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView

from .models import CustomUser
from .serializers import (
    UserSerializer, UserSerializerWithToken, LoginSerializer, 
    PasswordResetSerializer, PasswordResetConfirmSerializer, LogoutSerializer
)
from .tokens import account_activation_token, password_reset_token_generator
from django.contrib.auth.hashers import make_password

# Set up logging
logger = logging.getLogger(__name__)

class RegisterView(generics.GenericAPIView):
    """
    Register a new user with email and password. Sends a verification email upon successful registration.
    """
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Register a new user.",
        responses={
            200: openapi.Response("Please check your email to complete registration."),
            400: openapi.Response("User with this email already exists.")
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']

        if CustomUser.get_user_by_email(email):  # Use cached method
            logger.info(f"Registration attempt with existing email: {email}")
            return Response({'details': 'User with this email already exists.'}, status=status.HTTP_400_BAD_REQUEST)

        # Prepare email details
        try:
            token_data = {
                'full_name': serializer.validated_data['full_name'],
                'email': email,
                'password': make_password(serializer.validated_data['password']),
            }
            s = URLSafeTimedSerializer(settings.SECRET_KEY)
            token = s.dumps(token_data, salt='email-confirmation')
            
            current_site = get_current_site(request).domain
            verification_link = f'http://{current_site}/api/v1/verify-email/{token}/'

            email_subject = 'Activate Your Account'
            email_body = render_to_string('activate.html', {
                'verification_link': verification_link,
            })

            email_message = EmailMessage(
                subject=email_subject,
                body=email_body,
                from_email=settings.EMAIL_HOST_USER,
                to=[email]
            )
            email_message.content_subtype = 'html'
            email_message.send()

            logger.info(f"Verification email sent to: {email}")
            return Response({'details': 'Please check your email to complete registration.'}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error during registration: {str(e)}", exc_info=True)
            return Response({'details': f'Error sending email: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class VerifyEmailView(APIView):
    """
    Verifies the user's email using the token sent in the verification email.
    """
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Verify a user's email using the provided token.",
        responses={
            200: openapi.Response("Email verification successful."),
            400: openapi.Response("Invalid or expired verification link.")
        }
    )
    def get(self, request, token, *args, **kwargs):
        s = URLSafeTimedSerializer(settings.SECRET_KEY)
        try:
            # Decode the token
            token_data = s.loads(token, salt='email-confirmation', max_age=3600)  # 1 hour expiration
            email = token_data.get('email')

            if CustomUser.get_user_by_email(email):  # Use cached method
                logger.warning(f"Verification attempt with already verified email: {email}")
                return render(request, 'email_verification_failed.html', {'error': 'Email already verified.'})

            # Create and activate the user
            user = CustomUser.objects.create(
                full_name=token_data['full_name'],
                email=email,
                password=token_data['password'],
                is_active=True
            )
            
            # Invalidate cache to ensure fresh data
            cache.delete(f"user_email_{email}")
            logger.info(f"Email verification successful for: {email}")
            return render(request, 'email_success.html', {'message': 'Email verification successful'})

        except SignatureExpired:
            logger.warning("Verification link expired.")
            return render(request, 'email_verification_failed.html', {'error': 'The verification link has expired.'})
        except BadSignature:
            logger.warning("Invalid verification link.")
            return render(request, 'email_verification_failed.html', {'error': 'Invalid verification link.'})
        except Exception as e:
            logger.error(f"Unexpected error during email verification: {str(e)}", exc_info=True)
            return render(request, 'email_verification_failed.html', {'error': f'An unexpected error occurred: {str(e)}'})

class LoginView(generics.GenericAPIView):
    """
    Login a user using email and password.
    """
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Login a user.",
        responses={
            200: openapi.Response("Successful login with access and refresh tokens."),
            401: openapi.Response("Invalid email or password.")
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        user = CustomUser.get_user_by_email(email)  # Use cached method

        if user and user.check_password(password):
            refresh = RefreshToken.for_user(user)
            data = {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'full_name': user.full_name,
                    'is_active': user.is_active,
                }
            }
            logger.info(f"User logged in: {email}")
            return Response(data, status=status.HTTP_200_OK)
        else:
            logger.warning(f"Invalid login attempt for email: {email}")
            return Response({'error': 'Invalid email or password'}, status=status.HTTP_401_UNAUTHORIZED)

class PasswordResetView(generics.GenericAPIView):
    """
    Request a password reset for a user. Sends a password reset email.
    """
    serializer_class = PasswordResetSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Request a password reset.",
        responses={
            200: openapi.Response("Password reset instructions have been sent to your email."),
            400: openapi.Response("Invalid email address.")
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        user = CustomUser.get_user_by_email(email)  # Use cached method

        if user:
            self.send_password_reset_email(user.id)
            logger.info(f"Password reset requested for email: {email}")

        return Response({'message': 'Password reset instructions have been sent to your email'}, status=status.HTTP_200_OK)

    def send_password_reset_email(self, user_id, request):
        """
        Send a password reset email to the user with the given ID.
        """
        try:
            user = CustomUser.objects.get(id=user_id)
            token = password_reset_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))

            domain = get_current_site(request).domain
            reset_link = f'http://{domain}/api/v1/password-reset-confirm/{uid}/{token}/'

            email_subject = 'Password Reset'
            email_body = render_to_string('password_reset_email.html', {
                'user': user,
                'reset_link': reset_link,
            })

            email = EmailMessage(
                subject=email_subject,
                body=email_body,
                from_email=settings.EMAIL_HOST_USER,
                to=[user.email],
            )
            email.content_subtype = 'html'
            email.send()
            logger.info(f"Password reset email sent to: {user.email}")
        except Exception as e:
            logger.error(f"Error sending password reset email: {str(e)}", exc_info=True)

class PasswordResetConfirmView(generics.GenericAPIView):
    """
    Confirm a password reset by providing the new password along with the token and user ID.
    """
    serializer_class = PasswordResetConfirmSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Confirm password reset with the provided token.",
        responses={
            200: openapi.Response("Password reset successful."),
            400: openapi.Response("Invalid token or user.")
        }
    )
    def post(self, request, uidb64, token, *args, **kwargs):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = CustomUser.get_user_by_id(uid)  # Use cached method

            if user and password_reset_token_generator.check_token(user, token):
                data = {
                    'uid': uidb64,
                    'token': token,
                    'password': request.data.get('password')
                }
                serializer = self.get_serializer(data=data)
                serializer.is_valid(raise_exception=True)

                # Set the new password
                user.set_password(serializer.validated_data['password'])
                user.save()

                logger.info(f"Password reset successful for user: {user.email}")
                return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)
            else:
                logger.warning(f"Invalid token or user for password reset. UID: {uid}")
                return Response({'error': 'Invalid token or user'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error during password reset confirmation: {str(e)}", exc_info=True)
            return Response({'error': 'An unexpected error occurred'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class LogoutView(generics.GenericAPIView):
    """
    Logout a user by blacklisting the refresh token.
    """
    serializer_class = LogoutSerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Logout a user by invalidating their refresh token.",
        responses={
            200: openapi.Response("Logout successful."),
            400: openapi.Response("Invalid refresh token.")
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            refresh_token = serializer.validated_data['refresh_token']
            token = RefreshToken(refresh_token)
            token.blacklist()
            logger.info(f"User logged out: {request.user.email}")
            return Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error during logout: {str(e)}", exc_info=True)
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class CustomTokenRefreshView(TokenRefreshView):
    """
    Refresh the JWT token for a user.
    """
    pass
