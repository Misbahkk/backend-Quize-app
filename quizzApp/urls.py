from django.urls import path 
from .views import registerView ,LoginView ,UserView ,LogoutView,PasswordResetRequestView,PasswordResetConfirmView,ChangePasswordView,QuizAndSuggestionView,SuggestionView,ListMCQsView,EditMCQView,DeleteMCQView, DeleteQuizView,QuestionView,JoinQuizView,QuestionsParticipentsView,SubmitResponseView,QuizResultsView

from rest_framework_simplejwt.views import TokenRefreshView



urlpatterns = [
    path('register', registerView.as_view()),
    path('login', LoginView.as_view()),
    path('user', UserView.as_view()),
    path('logout', LogoutView.as_view()),
    path('request-reset-password', PasswordResetRequestView.as_view()),
    path('reset-password/', PasswordResetConfirmView.as_view()),
    path('change-password', ChangePasswordView.as_view()),
    path('quiz-suggestions/', QuizAndSuggestionView.as_view(), name='quiz_suggestions'),
    path("suggestion-quize/", SuggestionView.as_view(), name="suggetion"),
    path('mcqs/', ListMCQsView.as_view(), name='list_mcqs'),
    path('mcqs/<int:pk>/', QuestionView.as_view(), name='list_mcqs'),
    path('mcqs/edit/<int:pk>/', EditMCQView.as_view(), name='edit_mcq'),
    path('mcqs/delete/<int:pk>/', DeleteMCQView.as_view(), name='delete_mcq'),
    path('mcqs/deleteQuiz/<int:pk>/', DeleteQuizView.as_view(), name='delete_mcq'),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("join-quiz/", JoinQuizView.as_view(), name="join_quiz"),
    path("<int:quiz_id>/question-particepent/", QuestionsParticipentsView.as_view(), name="question_participent"),
    path("<int:quiz_id>/submit-responce/", SubmitResponseView.as_view(), name="submit_repsponce"),
    path("<int:quiz_id>/results/", QuizResultsView.as_view(), name="result")

]