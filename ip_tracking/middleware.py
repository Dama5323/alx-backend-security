from django.utils.timezone import now
from django.http import HttpResponseForbidden
from .models import RequestLog, BlockedIP

class LogIPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Get client IP address
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        ip = x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')

        # Check if IP is blacklisted
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("<h1>403 Forbidden</h1><p>Your IP is blocked.</p>")


        # Log the request
        RequestLog.objects.create(
            ip_address=ip,
            timestamp=now(),
            path=request.path
        )

        # Proceed with the request
        response = self.get_response(request)
        return response
