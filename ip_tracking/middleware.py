from .models import RequestLog
from django.utils.timezone import now

class LogIPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Get IP address
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        ip = x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')
        
        # Save request info
        RequestLog.objects.create(
            ip_address=ip,
            timestamp=now(),
            path=request.path
        )

        response = self.get_response(request)
        return response
