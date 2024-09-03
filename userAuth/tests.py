import logging
from django.urls import reverse
from django.core import mail
from rest_framework import status
from rest_framework.test import APITestCase
from .models import CustomUser, Profile
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from rest_framework_simplejwt.tokens import RefreshToken
from .tokens import password_reset_token_generator
from licenseApplication.models import NewLicenseApplication

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class UserTests(APITestCase):

    def setUp(self):
        self.user = CustomUser.objects.create_user(
            email='testuser@example.com', 
            full_name='Test User', 
            password='password123'
        )
        logger.info("Set up test user with email 'testuser@example.com'")

    def log_request_response(self, method, url, data=None, response=None):
        logger.info(f"Request method: {method}")
        logger.info(f"Request URL: {url}")
        if data:
            logger.info(f"Request body: {data}")
        if response:
            logger.info(f"Response status: {response.status_code}")
            logger.info(f"Response content: {response.content.decode('utf-8')}")
        print(f"Request method: {method}")
        print(f"Request URL: {url}")
        if data:
            print(f"Request body: {data}")
        if response:
            print(f"Response status: {response.status_code}")
            print(f"Response content: {response.content.decode('utf-8')}")

    def test_register_user(self):
        url = reverse('register')
        data = {
            'email': 'newuser@example.com',
            'full_name': 'New User',
            'password': 'Password_123',
            'confirm_password': 'Password_123'
        }
        response = self.client.post(url, data, format='json')
        self.log_request_response('POST', url, data, response)

        try:
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(CustomUser.objects.count(), 1)  # Active users
            self.assertEqual(CustomUser.objects.filter(is_active=False).count(), 1)  # Inactive users
            logger.info("test_register_user PASSED")
        except AssertionError as e:
            logger.error(f"test_register_user FAILED: {e}")
            raise

    def test_register_existing_user(self):
        url = reverse('register')
        data = {
            'email': 'testuser@example.com',  # Existing email
            'full_name': 'New User',
            'password': 'password123',
            'confirm_password': 'password123'
        }
        response = self.client.post(url, data, format='json')
        self.log_request_response('POST', url, data, response)

        try:
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            logger.info("test_register_existing_user PASSED")
        except AssertionError as e:
            logger.error(f"test_register_existing_user FAILED: {e}")
            raise

    def test_login_user(self):
        url = reverse('login')
        data = {
            'email': 'testuser@example.com',
            'password': 'password123',
        }
        response = self.client.post(url, data, format='json')
        self.log_request_response('POST', url, data, response)

        try:
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertIn('access', response.data)
            self.assertIn('refresh', response.data)
            logger.info("test_login_user PASSED")
        except AssertionError as e:
            logger.error(f"test_login_user FAILED: {e}")
            raise

    def test_login_invalid_credentials(self):
        url = reverse('login')
        data = {
            'email': 'testuser@example.com',
            'password': 'wrongpassword',
        }
        response = self.client.post(url, data, format='json')
        self.log_request_response('POST', url, data, response)

        try:
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
            logger.info("test_login_invalid_credentials PASSED")
        except AssertionError as e:
            logger.error(f"test_login_invalid_credentials FAILED: {e}")
            raise

    def test_password_reset(self):
        url = reverse('password-reset')
        data = {'email': 'testuser@example.com'}
        response = self.client.post(url, data, format='json')
        self.log_request_response('POST', url, data, response)

        try:
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(len(mail.outbox), 1)
            self.assertIn('Password Reset', mail.outbox[0].subject)
            logger.info("test_password_reset PASSED")
        except AssertionError as e:
            logger.error(f"test_password_reset FAILED: {e}")
            raise

    def test_password_reset_invalid_email(self):
        url = reverse('password-reset')
        data = {'email': 'nonexistent@example.com'}
        response = self.client.post(url, data, format='json')
        self.log_request_response('POST', url, data, response)

        try:
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
            logger.info("test_password_reset_invalid_email PASSED")
        except AssertionError as e:
            logger.error(f"test_password_reset_invalid_email FAILED: {e}")
            raise

    def test_password_reset_confirm(self):
        uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        token = password_reset_token_generator.make_token(self.user)
        url = reverse('password-reset-confirm', kwargs={'uidb64': uid, 'token': token})
        response = self.client.get(url)
        self.log_request_response('GET', url, None, response)

        try:
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            logger.info("Password reset confirm GET PASSED")

            # Posting new password
            data = {'password': 'newpassword123'}
            response = self.client.post(url, data)
            self.log_request_response('POST', url, data, response)

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.user.refresh_from_db()
            self.assertTrue(self.user.check_password('newpassword123'))
            logger.info("test_password_reset_confirm PASSED")
        except AssertionError as e:
            logger.error(f"test_password_reset_confirm FAILED: {e}")
            raise

    def test_logout_user(self):
        refresh = RefreshToken.for_user(self.user)
        url = reverse('logout')
        data = {'refresh_token': str(refresh)}
        self.client.force_authenticate(user=self.user)
        response = self.client.post(url, data, format='json')
        self.log_request_response('POST', url, data, response)

        try:
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            logger.info("test_logout_user PASSED")
        except AssertionError as e:
            logger.error(f"test_logout_user FAILED: {e}")
            raise

    def test_profile_retrieval(self):
        profile, created = Profile.objects.get_or_create(user=self.user)
        if not created:
            profile.gender = 'Male'
            profile.save()

        url = reverse('profile-detail', kwargs={'pk': profile.pk})
        self.client.force_authenticate(user=self.user)
        response = self.client.get(url)
        self.log_request_response('GET', url, None, response)

        try:
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.data['gender'], 'Male')
            logger.info("test_profile_retrieval PASSED")
        except AssertionError as e:
            logger.error(f"test_profile_retrieval FAILED: {e}")
            raise

    def test_profile_not_found(self):
        non_existent_pk = 9999
        url = reverse('profile-detail', kwargs={'pk': non_existent_pk})
        self.client.force_authenticate(user=self.user)
        response = self.client.get(url)
        self.log_request_response('GET', url, None, response)

        try:
            self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
            logger.info("test_profile_not_found PASSED")
        except AssertionError as e:
            logger.error(f"test_profile_not_found FAILED: {e}")
            raise

    def test_profile_created_when_user_created(self):
        """Test that a Profile is created when a new CustomUser is created."""
        user = CustomUser.objects.create_user(
            email='newuser@example.com', 
            full_name='New User', 
            password='password123'
        )
        profile = Profile.objects.get(user=user)
        self.assertIsNotNone(profile)
        logger.info("test_profile_created_when_user_created PASSED")

    def test_profile_updated_when_application_created(self):
        """Test that the Profile is updated when a NewLicenseApplication is created."""
        # Ensure profile initially has no gender
        profile = Profile.objects.get(user=self.user)
        # self.assertEqual(profile.gender, '')

        # Create a NewLicenseApplication
        NewLicenseApplication.objects.create(
            user=self.user,
            first_name='Test',
            last_name='User',
            gender='male',
            date_of_birth='1990-01-01',
            mother_maiden_name='Jane Doe',
            NIN='12345678901',
            passport_photo= 'path/to/photo.jpg',
            phone_number = '08012345678',
            email = 'tester@mail.com',
            street_address ='1234 Ade street',
            local_government = 'localGovernment',
            state = 'userState',
            application_type='new'
        )

        try:
            # Reload the profile and check if it was updated
            profile.refresh_from_db()
            self.assertEqual(profile.gender, 'male')
           # self.assertEqual(profile.phone_number, '08012345678')
            logger.info("test_profile_updated_when_application_created PASSED")
        except AssertionError as e:
            logger.error(f"test_profile_updated_when_application_created FAILED: {e}")
            raise