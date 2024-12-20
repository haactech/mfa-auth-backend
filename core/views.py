from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.db import connection
from rest_framework import status

@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        return Response({"status": "healthy"})
    except Exception as e:
        return Response(
            {"status": "unhealthy", "error": str(e)},
            status=status.HTTP_503_SERVICE_UNAVAILABLE
        )