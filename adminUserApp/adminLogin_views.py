
from rest_framework.response import Response
from rest_framework import generics, status
from rest_framework_simplejwt.tokens import RefreshToken

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi


from userAuth.serializers import LoginSerializer, UserSerializer
from userAuth.views import BaseUserView
from userAuth.utils import logger, format_error_response, get_user_by_email


class AdminUserLogin(BaseUserView, generics.GenericAPIView):
    serializer_class = LoginSerializer
    @swagger_auto_schema(
        operation_description="Admin login",
        responses= {200:openapi.Response("Login Sucessful"), 401:openapi.Response('Unauthorised')}
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]
        user = get_user_by_email(email)
        
        if user and user.check_password(password):
            if user.is_staff:
                refresh = RefreshToken.for_user(user)
                logger.info(f"Admin logged in {email}")
                return Response({
                    'refresh': str(refresh), 
                    'access':str(refresh.access_token),
                    'user': UserSerializer(user).data}, 
                    status=status.HTTP_200_OK)
            else:
                logger.warning(f"Unauthorized admin login attempt for email {email}")
                return Response(format_error_response(
                    status_code= status.HTTP_403_FORBIDDEN,
                    error_code="FORBIDDEN",
                    message="You do not have admin access"
                    
                ), status=status.HTTP_403_FORBIDDEN)
        else:
            logger.warning(f"Invalid admin login attempt {email}")
            return Response(format_error_response(
                status_code=status.HTTP_401_UNAUTHORIZED,
                error_code= 'INVALID_CREDENTIALS',
                message = 'Invalid email or password.'
            ), status=status.HTTP_401_UNAUTHORIZED)