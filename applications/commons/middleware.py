


import logging

from django.http import HttpResponse
from django.urls import reverse, resolve
from django.shortcuts import redirect
from django.contrib import messages
logger = logging.getLogger(__name__)
import redis
from django.http import JsonResponse
from rest_framework_simplejwt.authentication import JWTAuthentication





class MyCustomLogMW:
    def __init__(self, get_response):
            self.get_response = get_response
            print("🔧 Middleware initialized")

    def __call__(self, request):
        # Just return get_response here; hooks are in separate methods
        return self.get_response(request)

    def process_view(self, request, view_func, view_args, view_kwargs):
        print("🔍 process_view hit")
        print(f"   View function: {view_func.__name__}")
        print(f"   Args: {view_args}, Kwargs: {view_kwargs}")
        # return None to continue as normal
        return None

    def process_exception(self, request, exception):
        print("🚨 process_exception hit")
        print(f"   Exception: {exception}")
        return HttpResponse("Something went wrong!", status=500)

    def process_template_response(self, request, response):
        print("🎨 process_template_response hit")
        # You can modify context data here if needed
        # response.context_data['middleware_info'] = "Processed by DebugMiddleware"
        return response
    





    

r = redis.Redis(host='localhost', port=6379, db=3)
class RateLimiterMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.rate_limit_seconds = 10 # 10 seconds rate limit
        self.max_requests = 5
    def __call__(self, request):

        
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        print(f"🔍 RateLimiterMiddleware: x_forwarded_for: {x_forwarded_for}")
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        print(f"-----   Detected IP: {ip}")
        redis_key = f"rate_limit:{ip}"
        
        r.incr(redis_key)
        r.expire(name=redis_key, time=self.rate_limit_seconds, nx=True)
        current = r.get(redis_key)
        
        
        
        time_left = r.ttl(redis_key)
        print (f"Current requests for {ip}: {current}; Time left: {time_left} seconds")
        
        if current and int(current) > self.max_requests:
            return JsonResponse({
                "error": "⛔ Rate limit exceeded. Please try again later.",
                "retry_after_seconds": time_left
            }, status=429)
        
        return self.get_response(request)