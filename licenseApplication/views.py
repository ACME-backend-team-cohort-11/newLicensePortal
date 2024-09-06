from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse, Http404
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError, PermissionDenied

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .models import NewLicenseApplication, RenewalLicenseApplication, ReissueLicenseApplication, ApplicationAudit
from .serializers import (
    NewLicenseApplicationSerializer,
    RenewalLicenseApplicationSerializer,
    ReissueLicenseApplicationSerializer,
    ApplicationAuditSerializer,
)
from .payment import verify_payment
from paymentApp.models import Payment

import logging

logger = logging.getLogger(__name__)
class PaymentVerificationError(Exception):
    pass

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

def handle_payment(request, application):
    payment_reference = request.data.get('reference')
    payment_amount = request.data.get('amount')
    transaction_id = request.data.get('transaction_id')

    if not payment_reference or not payment_amount:
        raise ValidationError("Payment details are required.")

    try:
        verification_response = verify_payment(payment_reference)
        if verification_response['data']['status'] != 'success':
            raise PaymentVerificationError("Payment verification failed.")
    except Exception as e:
        logger.error(f"Payment verification error: {str(e)}", exc_info=True)
        raise PaymentVerificationError(f"There was an error verifying the payment: {str(e)}")

    Payment.objects.create(
        user=request.user,
        application=application,
        transaction_id=transaction_id,
        reference=payment_reference,
        amount=payment_amount,
        status='COMPLETED'
    )

@method_decorator(csrf_exempt, name='dispatch')
class BaseLicenseApplicationView(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]
    
    def check_permissions(self, request):
        for permission in self.get_permissions():
            if not permission.has_permission(request, self):
                logger.warning(
                    f"Permission denied for user {request.user.id} on {self.__class__.__name__}. "
                    f"Permission class: {permission.__class__.__name__}"
                )
                self.permission_denied(
                    request,
                    message=getattr(permission, 'message', None),
                    code=getattr(permission, 'code', None)
                )


    @swagger_auto_schema(
        operation_description="Create a new license application with payment.",
        responses={
            201: openapi.Response("Application created successfully."),
            400: openapi.Response("Validation error or payment verification failed."),
            403: openapi.Response("Permission denied."),
            500: openapi.Response("Server error during application creation.")
        }
    )
    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            application = serializer.save(user=request.user, application_type=self.application_type)
            
            handle_payment(request, application)
            
            headers = self.get_success_headers(serializer.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
        except ValidationError as ve:
            logger.warning(f"Validation error in {self.__class__.__name__}: {str(ve)}")
            return Response(format_error_response(400, "VALIDATION_ERROR", str(ve)), status=status.HTTP_400_BAD_REQUEST)
        except PaymentVerificationError as pve:
            logger.error(f"Payment verification error in {self.__class__.__name__}: {str(pve)}")
            return Response(format_error_response(400, "PAYMENT_ERROR", str(pve)), status=status.HTTP_400_BAD_REQUEST)
        except PermissionDenied as pd:
            logger.warning(f"Permission denied in {self.__class__.__name__}: {str(pd)}")
            return Response(format_error_response(403, "PERMISSION_DENIED", str(pd)), status=status.HTTP_403_FORBIDDEN)
        except Exception as e:
            logger.error(f"Unexpected error in {self.__class__.__name__}: {str(e)}", exc_info=True)
            return Response(format_error_response(500, "SERVER_ERROR", "An unexpected error occurred."), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class NewLicenseApplicationListCreateView(BaseLicenseApplicationView):
    queryset = NewLicenseApplication.objects.all()
    serializer_class = NewLicenseApplicationSerializer
    application_type = NewLicenseApplication.NEW

class RenewalLicenseApplicationListCreateView(BaseLicenseApplicationView):
    queryset = RenewalLicenseApplication.objects.all()
    serializer_class = RenewalLicenseApplicationSerializer
    application_type = RenewalLicenseApplication.RENEWAL

class ReissueLicenseApplicationListCreateView(BaseLicenseApplicationView):
    queryset = ReissueLicenseApplication.objects.all()
    serializer_class = ReissueLicenseApplicationSerializer
    application_type = ReissueLicenseApplication.REISSUE

class LicenseApplicationDetailView(generics.RetrieveAPIView):
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        application_type = self.kwargs.get('application_type')
        application_map = {
            NewLicenseApplication.NEW: NewLicenseApplication,
            RenewalLicenseApplication.RENEWAL: RenewalLicenseApplication,
            ReissueLicenseApplication.REISSUE: ReissueLicenseApplication
        }
        return application_map.get(application_type, None).objects.all()

    def get_serializer_class(self):
        application_type = self.kwargs.get('application_type')
        serializer_map = {
            NewLicenseApplication.NEW: NewLicenseApplicationSerializer,
            RenewalLicenseApplication.RENEWAL: RenewalLicenseApplicationSerializer,
            ReissueLicenseApplication.REISSUE: ReissueLicenseApplicationSerializer
        }
        return serializer_map.get(application_type, None)

    @swagger_auto_schema(
        operation_description="Retrieve a specific license application.",
        responses={
            200: openapi.Response("License application retrieved successfully."),
            400: openapi.Response("Invalid application type provided."),
            403: openapi.Response("Permission denied."),
            404: openapi.Response("Application not found."),
            500: openapi.Response("Server error during retrieval.")
        }
    )
    def get(self, request, *args, **kwargs):
        try:
            return super().get(request, *args, **kwargs)
        except Http404:
            return Response(format_error_response(404, "NOT_FOUND", "Application not found."), status=status.HTTP_404_NOT_FOUND)
        except PermissionDenied:
            return Response(format_error_response(403, "PERMISSION_DENIED", "You do not have permission to access this application."), status=status.HTTP_403_FORBIDDEN)
        except Exception as e:
            logger.error(f"Error retrieving license application: {str(e)}", exc_info=True)
            return Response(format_error_response(500, "SERVER_ERROR", "An unexpected error occurred while retrieving the application."), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ApplicationAuditListView(generics.ListAPIView):
    serializer_class = ApplicationAuditSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        application_id = self.kwargs['application_id']
        return ApplicationAudit.objects.filter(application_id=application_id)

    @swagger_auto_schema(
        operation_description="List audits related to a specific application.",
        responses={
            200: openapi.Response("List of application audits."),
            403: openapi.Response("Permission denied."),
            404: openapi.Response("Application not found."),
            500: openapi.Response("Server error during audit retrieval.")
        }
    )
    def get(self, request, *args, **kwargs):
        try:
            return super().get(request, *args, **kwargs)
        except Http404:
            return Response(format_error_response(404, "NOT_FOUND", "Application not found."), status=status.HTTP_404_NOT_FOUND)
        except PermissionDenied:
            return Response(format_error_response(403, "PERMISSION_DENIED", "You do not have permission to access these audits."), status=status.HTTP_403_FORBIDDEN)
        except Exception as e:
            logger.error(f"Error retrieving application audits: {str(e)}", exc_info=True)
            return Response(format_error_response(500, "SERVER_ERROR", "An unexpected error occurred while retrieving the audits."), status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ApplicationSlipView(LoginRequiredMixin, View):
    @swagger_auto_schema(
        operation_description="Display the application slip and provide a printer-friendly version.",
        responses={
            200: openapi.Response("Application slip rendered successfully."),
            403: openapi.Response("Permission denied."),
            404: openapi.Response("Application not found."),
            500: openapi.Response("Server error during slip rendering.")
        }
    )
    def get(self, request, application_type, application_id, *args, **kwargs):
        try:
            application = self.get_application(application_type, application_id)
            payments = Payment.objects.filter(application=application)
            context = {
                'application': application,
                'payments': payments,
                'is_printable': 'print' in request.GET,
            }
            template_name = 'appSlip/application_slip_print.html' if context['is_printable'] else 'appSlip/application_slip.html'
            return render(request, template_name, context)
        except Http404:
            return HttpResponse("Application not found.", status=status.HTTP_404_NOT_FOUND)
        except PermissionDenied:
            return HttpResponse("You do not have permission to view this application slip.", status=status.HTTP_403_FORBIDDEN)
        except Exception as e:
            logger.error(f"Error displaying application slip: {str(e)}", exc_info=True)
            return HttpResponse("An error occurred while displaying the application slip.", status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get_application(self, application_type, application_id):
        application_map = {
            'new': NewLicenseApplication,
            'renewal': RenewalLicenseApplication,
            'reissue': ReissueLicenseApplication,
        }
        model = application_map.get(application_type)
        if model is None:
            raise Http404("Invalid application type")
        return get_object_or_404(model, pk=application_id, user=self.request.user)