import boto3
from botocore.exceptions import ClientError
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
import logging
from typing import Dict, Optional, Any

logger = logging.getLogger(__name__)

class EmailService:
    def __init__(self):
        self.ses_client = boto3.client(
            'ses',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_SES_REGION
        )
        self.sender = settings.DEFAULT_FROM_EMAIL

    def _render_email_template(self, template_name: str, context: Dict[str, Any]) -> tuple:
        """
        Renderiza las plantillas HTML y texto plano del correo
        """
        html_template = f"emails/{template_name}.html"
        text_template = f"emails/{template_name}.txt"

        html_content = render_to_string(html_template, context)
        try:
            text_content = render_to_string(text_template, context)
        except:
            # Si no existe plantilla de texto, genera una versión sin HTML
            text_content = strip_tags(html_content)

        return html_content, text_content

    def send_email(
        self,
        to_email: str,
        subject: str,
        template_name: str,
        context: Dict[str, Any],
        reply_to: Optional[str] = None
    ) -> bool:
        """
        Envía un correo electrónico usando Amazon SES
        """
        try:
            html_content, text_content = self._render_email_template(template_name, context)

            email_message = {
                'Source': self.sender,
                'Destination': {
                    'ToAddresses': [to_email]
                },
                'Message': {
                    'Subject': {
                        'Data': subject,
                        'Charset': 'UTF-8'
                    },
                    'Body': {
                        'Text': {
                            'Data': text_content,
                            'Charset': 'UTF-8'
                        },
                        'Html': {
                            'Data': html_content,
                            'Charset': 'UTF-8'
                        }
                    }
                }
            }

            if reply_to:
                email_message['ReplyToAddresses'] = [reply_to]

            response = self.ses_client.send_email(**email_message)
            
            logger.info(
                f"Email sent successfully to {to_email}. MessageId: {response['MessageId']}"
            )
            return True

        except ClientError as e:
            error = e.response['Error']
            logger.error(
                f"Failed to send email to {to_email}. "
                f"Error: {error['Message']}, "
                f"Code: {error['Code']}"
            )
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending email to {to_email}: {str(e)}")
            return False

    @classmethod
    def send_verification_email(cls, user, verification_token):
        """
        Envía el correo de verificación de cuenta
        """
        email_service = cls()
        verification_url = f"{settings.FRONTEND_URL}/verify-email/{verification_token}"
        
        context = {
            'user': user,
            'verification_url': verification_url,
            'site_name': settings.SITE_NAME
        }

        return email_service.send_email(
            to_email=user.email,
            subject=f"Verify your {settings.SITE_NAME} account",
            template_name='account_verification',
            context=context
        )

    @classmethod
    def send_mfa_enabled_notification(cls, user):
        """
        Notifica al usuario cuando MFA es activado
        """
        email_service = cls()
        
        context = {
            'user': user,
            'site_name': settings.SITE_NAME,
            'security_url': f"{settings.FRONTEND_URL}/security"
        }

        return email_service.send_email(
            to_email=user.email,
            subject=f"Two-Factor Authentication Enabled - {settings.SITE_NAME}",
            template_name='mfa_enabled',
            context=context
        )

    @classmethod
    def send_security_alert(cls, user, alert_type: str, details: Dict[str, Any]):
        """
        Envía alertas de seguridad al usuario
        """
        email_service = cls()
        
        context = {
            'user': user,
            'alert_type': alert_type,
            'details': details,
            'site_name': settings.SITE_NAME,
            'security_url': f"{settings.FRONTEND_URL}/security"
        }

        return email_service.send_email(
            to_email=user.email,
            subject=f"Security Alert - {settings.SITE_NAME}",
            template_name='security_alert',
            context=context
        )