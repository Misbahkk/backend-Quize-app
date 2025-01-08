from django.contrib.auth.models import AbstractUser
from django.db import models
from datetime import datetime,timedelta
# from django.contrib.auth import get_user_model

# user_model = get_user_model()



class User(AbstractUser):
    name =  models.CharField(max_length=255)
    email = models.CharField(max_length=255,unique=True)
    password = models.CharField(max_length=255)
    username =  None

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    ROLE_CHOICES = [
        ('student', 'Student'),
        ('teacher', 'Teacher'),
    ]
    
    role = models.CharField(max_length=7, choices=ROLE_CHOICES, default='student')
    
    #   # Password reset fields
    # reset_token = models.CharField(max_length=30, null=True, blank=True)
    # reset_token_expiry = models.DateTimeField(null=True, blank=True)



    # OTP fields for password reset
    otp_code = models.CharField(max_length=4, null=True, blank=True)
    otp_expiry = models.DateTimeField(null=True, blank=True)

    def set_otp(self):
        from random import randint
        self.otp_code = str(randint(1000, 9999))  # Generate a 4-digit OTP
        self.otp_expiry = datetime.now() + timedelta(minutes=10)  # OTP expires in 10 minutes
        self.save()




class Quiz(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    course_name = models.CharField(max_length=255)
    subject = models.CharField(max_length=255)
    code = models.CharField(max_length=10,unique=True,null=True,blank=True)
    total_questions = models.IntegerField()
    passing_percentage = models.IntegerField()
    scheduled_date_time = models.DateTimeField()
    created_by = models.ForeignKey('quizzApp.User', on_delete=models.CASCADE, related_name="quizzes")

    def __str__(self):
        return self.title
    

class Question(models.Model):
    quiz = models.ForeignKey(Quiz, on_delete=models.CASCADE, related_name="questions")
    text = models.TextField()
    image = models.ImageField(upload_to='questions/images/', blank=True, null=True)
    tag = models.CharField(max_length=100)
    options = models.JSONField()  # Store options as a JSON object (e.g., {"A": "Option A", "B": "Option B", ...})
    correct_option = models.CharField(max_length=1)  # Store the correct answer key (e.g., "A", "B", etc.)
    created_by = models.ForeignKey('quizzApp.User', on_delete=models.CASCADE, related_name="created_questions")

    def __str__(self):
        return f"{self.quiz.title}: {self.text}"





class Suggestion(models.Model):
    topic = models.CharField(max_length=255)
    created_by = models.ForeignKey('quizzApp.User', on_delete=models.CASCADE, related_name='suggestions')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.topic




class Participant(models.Model):
    name = models.CharField(max_length=100)
    is_active = models.BooleanField(default=False)
    email = models.EmailField(max_length=254,blank=True,null=True) 
    quiz_participent = models.ForeignKey(Quiz,on_delete=models.CASCADE,related_name="participants")
    total_attempts = models.IntegerField(default=0)
    passed_quiz_count = models.IntegerField(default=0)
    failed_quiz_count = models.IntegerField(default=0)

    def __str__(self):
        return self.name
    


class ResponseParticipent(models.Model):
    participant = models.ForeignKey('Participant', on_delete=models.CASCADE)
    question_response = models.ForeignKey('Question',on_delete=models.CASCADE, related_name="responses")
    select_option = models.CharField(max_length=200)
    is_correct = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.participant.name} - {self.question_response.text}"
    




