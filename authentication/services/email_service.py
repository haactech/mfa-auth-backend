from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
import logging

logger = logging.getLogger(__name__)

class EmailService:
    @staticmethod
    def send_verification_email(user, verification_token):
        try:
            # TODO: Implementar SES
            # Por ahora, solo logueamos el email
            logger.info(f"Verification email would be sent to {user.email} with token {verification_token}")
            return True
        except Exception as e:
            logger.error(f"Error sending verification email: {str(e)}")
            return False