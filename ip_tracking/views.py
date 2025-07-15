from django.shortcuts import render
from django.http import HttpResponse
from django_ratelimit.decorators import ratelimit

# Anonymous users: 5 requests per minute
@ratelimit(key='ip', rate='5/m', method='POST', block=True)
# Authenticated users: 10 requests per minute
@ratelimit(key='user', rate='10/m', method='POST', block=True)
def login_view(request):
    return HttpResponse("Login successful or form rendered.")
