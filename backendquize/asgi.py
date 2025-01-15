
import os

from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from quizzApp.routing import websocket_urlpatterns
from django.urls import path
from quizzApp import consumer

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backendquize.settings')

application =   ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AuthMiddlewareStack(
         URLRouter([
            path('ws/quiz/<int:quiz_id>/', consumer.QuizConsumer.as_asgi()),
        ])
    ),
})
