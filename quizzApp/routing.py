from django.urls import re_path
from . import consumer

websocket_urlpatterns = [
    re_path(r'ws/quiz/(?P<quiz_id>\d+)/$', consumer.QuizConsumer.as_asgi()),
]
