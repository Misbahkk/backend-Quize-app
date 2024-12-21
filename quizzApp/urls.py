from django.urls import path 
from .views import registerView ,LoginView ,UserView ,LogoutView,PasswordResetRequestView,PasswordResetConfirmView,ChangePasswordView,QuizAndSuggestionView,ListMCQsView,EditMCQView,DeleteMCQView



urlpatterns = [
    path('register', registerView.as_view()),
    path('login', LoginView.as_view()),
    path('user', UserView.as_view()),
    path('logout', LogoutView.as_view()),
    path('request-reset-password', PasswordResetRequestView.as_view()),
    path('reset-password/', PasswordResetConfirmView.as_view()),
    path('change-password', ChangePasswordView.as_view()),
    path('quiz-suggestions/', QuizAndSuggestionView.as_view(), name='quiz_suggestions'),
    path('mcqs/', ListMCQsView.as_view(), name='list_mcqs'),
    path('mcqs/edit/<int:pk>/', EditMCQView.as_view(), name='edit_mcq'),
    path('mcqs/delete/<int:pk>/', DeleteMCQView.as_view(), name='delete_mcq'),
]