from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework import status
from licenseApplication.models import NewLicenseApplication, ReissueLicenseApplication, RenewalLicenseApplication
from unittest.mock import patch


from django.test import TestCase
from rest_framework import serializers
from .serializers import DynamicDashboardStatsSerializer

class DashboardStatsViewTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        # Creating a sample data
        NewLicenseApplication.objects.create()
        NewLicenseApplication.objects.create()
        ReissueLicenseApplication.objects.create()
        RenewalLicenseApplication.objects.create()
        RenewalLicenseApplication.objects.create()
        RenewalLicenseApplication.objects.create()
    
    @patch('licenseApplication.models.NewLicenseApplication.objects.count')
    def test_get_dashboard_stats(self, mock_count):
        # Make GET request to the view
        response = self.client.get('/dashboard/stats/')

        mock_count.side_effect = Exception("Server error")

        
        # Expected data
        expected_data = {
            'total_new_applications': 2,
            'total_reissues': 1,
            'total_renewals': 3,
            'total_completed': 6
        }
        
        # Assertions
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, expected_data)

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertEqual(response.data['detail'], "Internal server error")

class DynamicDashboardStatsSerializerTest(TestCase):
    def test_dynamic_dashboard_stats_serializer(self):
        # Sample data
        data = {
            'total_new_applications': 2,
            'total_reissues': 1,
            'total_renewals': 3,
            'total_completed': 6
        }

        # Initialize the serializer with the sample data
        serializer = DynamicDashboardStatsSerializer(data=data)
        
        # Validate the serializer
        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.data, data)