from django.conf import settings
from django.core.cache import cache
from django.shortcuts import render
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.contrib.auth.hashers import make_password

from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken

from drf_yasg.utils import swagger_auto_schema 
from drf_yasg import openapi

from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

from .models import CustomUser
from .serializers import (UserSerializer, LoginSerializer,  LogoutSerializer)
from .utils import logger, format_error_response, get_user_by_email, send_email
from .permissions import IsRegularUser


# Base class for user-related views
class BaseUserView(APIView):
    permission_classes = [AllowAny]

    def create_token_and_send_email(self, serializer_data, request):
        token_data = {
            'full_name': serializer_data['full_name'],
            'email': serializer_data['email'],
            'password': make_password(serializer_data['password']),
        }
        s = URLSafeTimedSerializer(settings.SECRET_KEY)
        token = s.dumps(token_data, salt='email-confirmation')

        current_site = get_current_site(request).domain
        verification_link = f'http://{current_site}/api/v1/verify-email/{token}/'

        email_body = render_to_string('email/activate.html', {'verification_link': verification_link})
        send_email('Activate Your Account', email_body, serializer_data['email'])

# Views
class RegisterView(BaseUserView, generics.GenericAPIView):
    serializer_class = UserSerializer

    @swagger_auto_schema(
        operation_description="Register a new user.",
        responses={
            200: openapi.Response("Please check your email to complete registration."),
            400: openapi.Response("User with this email already exists.")
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if not serializer.is_valid():
            logger.warning("Validation errors during registration.")
            return Response(format_error_response(
                status_code=status.HTTP_400_BAD_REQUEST,
                error_code="VALIDATION_ERROR",
                message="Invalid or incomplete data provided.",
                details=serializer.errors
            ), status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data['email']
        if get_user_by_email(email):
            logger.info(f"Registration attempt with existing email: {email}")
            return Response(format_error_response(
                status_code=status.HTTP_400_BAD_REQUEST,
                error_code="USER_EXISTS",
                message="User with this email already exists.",
                details={"email": email}
            ), status=status.HTTP_400_BAD_REQUEST)

        try:
            self.create_token_and_send_email(serializer.validated_data, request)
            return Response({'details': 'Please check your email to complete registration.'}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error during registration: {str(e)}", exc_info=True)
            return Response(format_error_response(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                error_code="EMAIL_ERROR",
                message="Error sending email.",
                details={"exception": str(e)}
            ), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class VerifyEmailView(BaseUserView):

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
            token_data = s.loads(token, salt='email-confirmation', max_age=3600)
            email = token_data.get('email')

            if get_user_by_email(email):
                logger.warning(f"Verification attempt with already verified email: {email}")
                return Response(format_error_response(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    error_code="EMAIL_ALREADY_VERIFIED",
                    message="Email already verified.",
                    details={"email": email}
                ), status=status.HTTP_400_BAD_REQUEST)

            CustomUser.objects.create(
                full_name=token_data['full_name'],
                email=email,
                password=token_data['password'],
                is_active=True
            )
            cache.delete(f"user_email_{email}")

            logger.info(f"Email verification successful for: {email}")
            return render(request, 'email/email_success.html',{'message': 'Email verification successful'}, status=status.HTTP_200_OK)

        except SignatureExpired:
            logger.warning("Verification link expired.")
            return Response(format_error_response(
                status_code=status.HTTP_400_BAD_REQUEST,
                error_code="LINK_EXPIRED",
                message="The verification link has expired."
            ), status=status.HTTP_400_BAD_REQUEST)
        except BadSignature:
            logger.warning("Invalid verification link.")
            return Response(format_error_response(
                status_code=status.HTTP_400_BAD_REQUEST,
                error_code="INVALID_LINK",
                message="Invalid verification link."
            ), status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Unexpected error during email verification: {str(e)}", exc_info=True)
            return Response(format_error_response(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                error_code="VERIFICATION_ERROR",
                message="An unexpected error occurred.",
                details={"exception": str(e)}
            ), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserLoginView(BaseUserView, generics.GenericAPIView):
    serializer_class = LoginSerializer

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
        user = get_user_by_email(email)

        if user and user.check_password(password):
            if not user.is_staff:
                refresh = RefreshToken.for_user(user)
                logger.info(f"User logged in: {email}")
                return Response({
                    'refresh': str(refresh), 
                    'access': str(refresh.access_token),
                    'user': UserSerializer(user).data}, 
                    status=status.HTTP_200_OK)
            else:
                logger.warnng(f"Admin attempted to log in via user login {email}")
                return Response(format_error_response(
                    status_code=status.HTTP_403_FORBIDDEN,
                    error_code= 'FORBIDDEN',
                    message= "Admins cannot user this login route"
                ), status=status.HTTP_403_FORBIDDEN)
        else:
            logger.warning(f"Invalid login attempt for email: {email}")
            return Response(format_error_response(
                status_code=status.HTTP_401_UNAUTHORIZED,
                error_code="INVALID_CREDENTIALS",
                message="Invalid email or password.",
                details={"email": email}
            ), status=status.HTTP_401_UNAUTHORIZED)


class LogoutView(generics.GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = [IsAuthenticated,  IsRegularUser]

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
            return Response(format_error_response(
                status_code=status.HTTP_400_BAD_REQUEST,
                error_code="LOGOUT_ERROR",
                message="An error occurred during logout.",
                details={"exception": str(e)}
            ), status=status.HTTP_400_BAD_REQUEST)

