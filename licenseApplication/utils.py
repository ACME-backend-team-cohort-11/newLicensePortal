from rest_framework.exceptions import ValidationError, PermissionDenied
from .payment import verify_payment
from paymentApp.models import Payment
from userAuth.utils import logger



class PaymentVerificationError(Exception):
    pass



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
