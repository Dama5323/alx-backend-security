from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from .models import RequestLog, SuspiciousIP

@shared_task
def detect_suspicious_ips():
    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)

    # Flag IPs with > 100 requests/hour
    suspicious_ips = (RequestLog.objects
                      .filter(timestamp__gte=one_hour_ago)
                      .values('ip_address')
                      .annotate(count=models.Count('id'))
                      .filter(count__gt=100))

    for item in suspicious_ips:
        SuspiciousIP.objects.get_or_create(
            ip_address=item['ip_address'],
            reason="High request volume"
        )

    # Flag IPs accessing sensitive paths
    sensitive_paths = ['/admin', '/admin/', '/admin/login/', '/login']
    logs = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago,
        path__in=sensitive_paths
    )

    for log in logs:
        SuspiciousIP.objects.get_or_create(
            ip_address=log.ip_address,
            reason=f"Accessed sensitive path: {log.path}"
        )
