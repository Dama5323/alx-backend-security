from django.utils.timezone import now
from django.http import HttpResponseForbidden
from .models import RequestLog, BlockedIP
import requests
from django.core.cache import cache

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
        
        # Check cache for geolocation info
        geo_info = cache.get(ip)
        if not geo_info:
            try:
                response = requests.get(f"http://ip-api.com/json/{ip}").json()
                geo_info = {
                    "country": response.get("country", ""),
                    "city": response.get("city", "")
                }
                cache.set(ip, geo_info, timeout=60 * 60 * 24)  # cache for 24h
            except:
                geo_info = {"country": "", "city": ""}


        # Log the request
        RequestLog.objects.create(
            ip_address=ip,
            timestamp=now(),
            path=request.path
        )

        # Proceed with the request
        response = self.get_response(request)
        return response
