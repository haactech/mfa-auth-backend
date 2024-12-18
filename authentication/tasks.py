from django.utils import timezone
from django.db import transaction
from authentication.models import AuthenticationSession

@transaction.atomic
def cleanup_expired_sessions():
    AuthenticationSession.objects.filter(
        expires_at__lt=timezone.now()
    ).delete()