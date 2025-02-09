from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from django.contrib.auth import get_user_model
from .models import NewLicenseApplication, RenewalLicenseApplication, ReissueLicenseApplication, ApplicationAudit
from paymentApp.models import Payment
from unittest.mock import patch
from django.core.files.uploadedfile import SimpleUploadedFile
import logging
import os

# Create a temporary image file
image_path = os.path.join(os.path.dirname(__file__), 'assets\\test_image.PNG')
with open(image_path, 'rb') as f:
    image_content = f.read()
    
User = get_user_model()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LicenseApplicationViewsTestCase(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(email='test@example.com', password='testpass123', is_active=True)
        self.client.force_authenticate(user=self.user)
    
    def tearDown(self):
        # Log the result of each test
        result = 'PASSED' if self._outcome.success else 'FAILED'
        logger.info(f"{self._testMethodName}: {result}")

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

    @patch('licenseApplication.views.verify_payment')
    def test_create_new_license_application(self, mock_verify_payment):
        mock_verify_payment.return_value = {'data': {'status': 'success'}}
        url = reverse('new-license-application-list-create')
        
        # Prepare sample image content
        image_content = b'\x00\x01'  # Dummy image byte data for testing
        
        data = {
            'first_name': 'John',
            'last_name': 'Doe',
            'middle_name': 'Middle',
            'gender': 'male',
            'date_of_birth': '1990-01-01',
            'mother_maiden_name': 'Jane Smith',
            'NIN': '12345678901',
            'passport_photo': SimpleUploadedFile("photo.jpg", image_content, content_type="image/jpeg"),
            'phone_number': '08012345678',
            'email': 'tester@mail.com',
            'street_address': '1234 Ade street',
            'local_government_of_residence': 'localGovernment',
            'state_of_residence': 'userState',
            'height': '175.5',
            'blood_group': 'O+',
            'local_government_of_origin': 'localGovernment',
            'state_of_origin': 'userState',
            'nationality': 'Nigerian',
            'facial_mark': 'None',
            'require_glasses': False,
            'next_of_kin_phone_number': '08098765432',
            'next_of_kin_full_name': 'Jane Doe',
            'reference': 'TEST_REF_123',
            'amount': '1000.00',
            'transaction_id': 'TRANS_123',
            'application_type': 'new'
        }
        
        response = self.client.post(url, data, format='multipart')
        self.log_request_response('POST', url, data, response)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(NewLicenseApplication.objects.count(), 1)
        self.assertEqual(Payment.objects.count(), 1)

    @patch('licenseApplication.views.verify_payment')
    def test_create_renewal_license_application(self, mock_verify_payment):
        mock_verify_payment.return_value = {'data': {'status': 'success'}}
        url = reverse('renewal-license-application-list-create')
        data = {
            'email': 'renewal@example.com',
            'license_id': 'LIC123456',
            'reference': 'TEST_REF_456',
            'amount': '500.00',
            'transaction_id': 'TRANS_456'
        }
        response = self.client.post(url, data, format='multipart')
        self.log_request_response('POST', url, data, response)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(RenewalLicenseApplication.objects.count(), 1)
        self.assertEqual(Payment.objects.count(), 1)

    @patch('licenseApplication.views.verify_payment')
    def test_create_reissue_license_application(self, mock_verify_payment):
        mock_verify_payment.return_value = {'data': {'status': 'success'}}
        url = reverse('reissue-license-application-list-create')
        data = {
            'email': 'reissue@example.com',
            'license_id': 'LIC987654',
            'affidavit': SimpleUploadedFile("affidavit.pdf", b"file_content", content_type="application/pdf"),
            'police_report': SimpleUploadedFile("police_report.pdf", b"file_content", content_type="application/pdf"),
            'reference': 'TEST_REF_789',
            'amount': '1500.00',
            'transaction_id': 'TRANS_789'
        }
        response = self.client.post(url, data, format='multipart')
        self.log_request_response('POST', url, data, response)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(ReissueLicenseApplication.objects.count(), 1)
        self.assertEqual(Payment.objects.count(), 1)

    def test_list_new_license_applications(self):
        NewLicenseApplication.objects.create(
            user=self.user,
            first_name='John',
            last_name='Doe',
            middle_name='Middle',
            gender='male',
            date_of_birth='1990-01-01',
            mother_maiden_name='Jane Smith',
            NIN='12345678901',
            passport_photo='path/to/photo.jpg',
            phone_number='08012345678',
            email='tester@mail.com',
            street_address='1234 Ade street',
            local_government_of_residence='localGovernment',
            state_of_residence='userState',
            height='175.5',
            blood_group='O+',
            local_government_of_origin='localGovernment',
            state_of_origin='userState',
            nationality='Nigerian',
            facial_mark='None',
            require_glasses=False,
            next_of_kin_phone_number='08098765432',
            next_of_kin_full_name='Jane Doe',
            application_type='new'
        )
        
        url = reverse('new-license-application-list-create')
        response = self.client.get(url)
        self.log_request_response('GET', url, None, response)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

def test_retrieve_license_application_detail(self):
    application = NewLicenseApplication.objects.create(
        user=self.user,
        first_name='John',
        last_name='Doe',
        middle_name='Middle',
        gender='male',
        date_of_birth='1990-01-01',
        mother_maiden_name='Jane Smith',
        NIN='12345678901',
        passport_photo='path/to/photo.jpg',
        phone_number='08012345678',
        email='tester@mail.com',
        street_address='1234 Ade street',
        local_government_of_residence='localGovernment',
        state_of_residence='userState',
        height='175.5',
        blood_group='O+',
        local_government_of_origin='localGovernment',
        state_of_origin='userState',
        nationality='Nigerian',
        facial_mark='None',
        require_glasses=False,
        next_of_kin_phone_number='08098765432',
        next_of_kin_full_name='Jane Doe',
        application_type='new'
    )
    
    url = reverse('license-application-detail', kwargs={'application_type': 'new', 'pk': application.pk})
    response = self.client.get(url)
    self.log_request_response('GET', url, None, response)
    self.assertEqual(response.status_code, status.HTTP_200_OK)
    self.assertEqual(response.data['first_name'], 'John')

def test_list_application_audits(self):
    application = NewLicenseApplication.objects.create(
        user=self.user,
        first_name='John',
        last_name='Doe',
        middle_name='Middle',
        gender='male',
        date_of_birth='1990-01-01',
        mother_maiden_name='Jane Smith',
        NIN='12345678901',
        passport_photo='path/to/photo.jpg',
        phone_number='08012345678',
        email='tester@mail.com',
        street_address='1234 Ade street',
        local_government_of_residence='localGovernment',
        state_of_residence='userState',
        height='175.5',
        blood_group='O+',
        local_government_of_origin='localGovernment',
        state_of_origin='userState',
        nationality='Nigerian',
        facial_mark='None',
        require_glasses=False,
        next_of_kin_phone_number='08098765432',
        next_of_kin_full_name='Jane Doe',
        application_type='new'
    )
    
    ApplicationAudit.objects.create(
        application=application,
        old_status='pending',
        new_status='approved',
        changed_by=self.user
    )
    
    url = reverse('application-audit-list', kwargs={'application_id': application.pk})
    response = self.client.get(url)
    self.log_request_response('GET', url, None, response)
    self.assertEqual(response.status_code, status.HTTP_200_OK)
    self.assertEqual(len(response.data), 1)
    
class ApplicationSlipViewTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(email='test@example.com', password='testpass123', is_active=True)
        self.client.login(email='test@example.com', password='testpass123')
    
    def tearDown(self):
        # Log the result of each test
        result = 'PASSED' if self._outcome.success else 'FAILED'
        logger.info(f"{self._testMethodName}: {result}")

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

    def test_application_slip_view(self):
        application = NewLicenseApplication.objects.create(
            user=self.user,
            first_name='John',
            last_name='Doe',
            gender='male',
            date_of_birth='1990-01-01',
            mother_maiden_name='Jane Smith',
            NIN='12345678901',
            passport_photo='path/to/photo.jpg',
            phone_number = '08012345678',
            email = 'tester@mail.com',
            street_address ='1234 Ade street',
            local_government_of_residence='localGovernment',
            state_of_residence='userState',
            height='175.5',
            blood_group='O+',
            local_government_of_origin='localGovernment',
            state_of_origin='userState',
            nationality='Nigerian',
            facial_mark='None',
            require_glasses=False,
            next_of_kin_phone_number='08098765432',
            next_of_kin_full_name='Jane Doe',
            application_type='new'
        )
        Payment.objects.create(user=self.user, application=application, amount='1000.00', reference='TEST_REF_789')
        url = reverse('application_slip', kwargs={'application_type': 'new', 'application_id': application.pk})
        response = self.client.get(url)
        self.log_request_response('GET', url, None, response)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTemplateUsed(response, 'appSlip/application_slip.html')
        

    def test_application_slip_print_view(self):
        application = NewLicenseApplication.objects.create(
            user=self.user,
            first_name='John',
            last_name='Doe',
            gender='male',
            date_of_birth='1990-01-01',
            mother_maiden_name='Jane Smith',
            NIN='12345678901',
            passport_photo='path/to/photo.jpg',
            phone_number = '08012345678',
            email = 'tester@mail.com',
            street_address ='1234 Ade street',
            local_government_of_residence='localGovernment',
            state_of_residence='userState',
            height='175.5',
            blood_group='O+',
            local_government_of_origin='localGovernment',
            state_of_origin='userState',
            nationality='Nigerian',
            facial_mark='None',
            require_glasses=False,
            next_of_kin_phone_number='08098765432',
            next_of_kin_full_name='Jane Doe',
            application_type='new'
        )
        url = reverse('application_slip', kwargs={'application_type': 'new', 'application_id': application.pk})
        response = self.client.get(url, {'print': 'true'})
        self.log_request_response('GET', url, None, response)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTemplateUsed(response, 'appSlip/application_slip_print.html')

    def test_application_slip_invalid_type(self):
        url = reverse('application_slip', kwargs={'application_type': 'invalid', 'application_id': 1})
        response = self.client.get(url)
        self.log_request_response('GET', url, None, response)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
