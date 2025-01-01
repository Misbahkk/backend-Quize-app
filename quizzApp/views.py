from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from django.contrib.auth import update_session_auth_hash
from rest_framework.views import APIView
from rest_framework.views import Response
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.authentication import JWTAuthentication
from .serializers import UserSerializer
from .models import User
import jwt, datetime
from django.core.mail import send_mail
from django.utils import timezone
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from .generate_quiz import generate_quiz_questions, generate_quiz_code,get_suggestions, load_user_inputs, save_user_inputs,extract_line
from django.conf import settings
from .models import Quiz, Suggestion ,Question ,Participant,ResponseParticipent
from datetime import datetime, timedelta

class registerView(APIView):
    def post(self,request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
    

from django.contrib.auth import authenticate
class LoginView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        # response = super().post(request, *args, **kwargs)
        # Optional: Set access token in the cookie
        email = request.data.get("email")
        password = request.data.get("password")
        
        user = authenticate(request, username=email, password=password)
        if user:
            # Generate tokens
            refresh = RefreshToken.for_user(user)
            access = refresh.access_token
            
            # Send back the response with access token, refresh token, and username
            return Response({
                "access": str(access),
                "refresh": str(refresh),
                "name": user.name,
                "email": user.email , # Add username here
            })
       
        # response.set_cookie(
        #     key='access',
        #     value=response.data['access'],
        #     httponly=True,
        #     samesite='Lax'
        # )
        # response.set_cookie(
        #     key='refresh',
        #     value=response.data['refresh'],
        #     httponly=True,
        #     samesite='Lax'
        # )
        # return response
        else:
            return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)


class UserView(APIView):
    def get(self,request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise  AuthenticationFailed('UnAuthenticated!!')
        try:
            payload = jwt.decode(token,'secret',algorithms=['HS256'])

        except jwt.ExpiredSignatureError:

            raise AuthenticationFailed('UnAuthenticated!!')
        
        user = User.objects.filter(id=payload['id']).first()
        serializer= UserSerializer(user)

        return Response(serializer.data)
    

# class LoginView(APIView):
#     def post(self,request):
#         email = request.data['email']
#         password = request.data['password']

#         user = User.objects.filter(email=email).first()

#         if user is None:
#             raise AuthenticationFailed('User Not Found')
        
#         if not user.check_password(password):
#             raise AuthenticationFailed('Incorrect Password')
        

#         payload ={
#             'id':user.id,
#             'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=60),
#             'iat': datetime.datetime.utcnow()
#         }

#         token = jwt.encode(payload,'secret',algorithm='HS256').decode('utf-8')

#         response = Response()

#         response.set_cookie(key='jwt',value =token,httponly=True)
#         response.data={
#             'jwt':token
#         }
     
        
#         return response
    


class LogoutView(APIView):
    def post(self,request):
        responce = Response()
        responce.delete_cookie('jwt')
        responce.data={
            'message':'success'
        }
        return responce
    





class PasswordResetRequestView(APIView):
    def post(self, request):
        email = request.data.get('email')
        user = User.objects.filter(email=email).first()
        if user is None:
            return Response({'error': 'User with this email does not exist'}, status=404)
        # Generate and save OTP
        user.set_otp()
        OTP= user.otp_code
        # Send OTP via email
        send_mail(
            'Your Password Reset OTP',
            f'Your OTP code is: {OTP}',
            settings.EMAIL_HOST_PASSWORD,
            [user.email],
            fail_silently=False,
        )
        print("Ypur otp cde: ",OTP)

        return Response({'message': 'OTP sent to your email.'})



class PasswordResetConfirmView(APIView):
    def post(self, request):
        # email = request.data.get('email')
        otp_code = request.data.get('otp_code')
        new_password = request.data.get('password')
        confirm_password = request.data.get('confirm_password')

        if not otp_code or not new_password or not confirm_password:
            return Response({'error':"OTP , password , confirm password is required.. "},status=200)
        
        if new_password != confirm_password:
            return Response({'eror':'password or confirm password does not match'},status=400)

        user = User.objects.filter(otp_code=otp_code).first()

        if user is None or user.otp_expiry < timezone.now():
            return Response({'error':"Invalid or Expire OTP"},status=400)

  

      
        user.set_password(new_password)
        # Clear OTP fields after successful reset
        user.otp_code = None
        user.otp_expiry = None
        user.save()
        return Response({'message': 'Password has been reset successfully.'})







#TODO: Quize genration

class QuizAndSuggestionView(APIView):


    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request):
        """
        Handle POST requests to generate a quiz and topic suggestions.

        Args:
            request: The incoming HTTP request.

        Returns:
            JSON response containing quiz questions and suggestions.
        """
        print("Request body:", request.body)  # Raw body
        print("Request data:", request.data)  # Parsed data
        # Prompt input
        user = request.user
        prompt = request.data.get('prompt')
        
        if not prompt:
            return Response({"error": "Prompt is required"}, status=400)

        # Load previous user inputs and add new prompt
        # user_inputs = load_user_inputs(user)
        # print("Loaded user inputs:", user_inputs)
       
        # user_inputs.append(prompt)
        

        # Generate Quiz and Suggestions
        quiz_questions = generate_quiz_questions(prompt)
        quize_code = generate_quiz_code()
        # suggestions = get_suggestions(user_inputs)
        
        # save_user_inputs(user,suggestions)
         # Save quiz to the database
        # Save the quiz to the database
        quiz = Quiz.objects.create(
        title=prompt,
        description="Generated quiz",
        course_name="Default Course",  
        code = quize_code,
        subject="Default Subject",   
        total_questions=len(quiz_questions),
        passing_percentage=50,         
        scheduled_date_time=datetime.now(),
        created_by=user
    )
            # Create and link questions to the quiz
        for question_data in quiz_questions: 
            Question.objects.create(
            quiz=quiz,
            text=question_data['text'],  
            tag="",  
            options=question_data['options'],
            correct_option=question_data['correct_option'],
            created_by=user
            )
      


        
        print(question_data)
        mcqs = extract_line([f'{q['text']} , {q['options']} , {q['correct_option']}' for q in quiz_questions], ignore_keyword=["##", "Instructions"])
        # suggested_questions = extract_line(suggestions, ignore_keyword=["##", "Here are 6 one-line"])

        # mcq_question = [f"{q}" for q in mcqs]
        # segetion_question = [f"{q}" for q in suggest_q]

        # Send response
        return Response({
            "quiz_id": quiz.id,
            "quiz_code": quize_code,
            "quiz_questions": mcqs,
            # "suggestions": suggested_questions,
        })



class SuggestionView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request):
        """
        Handle POST requests to generate topic suggestions.

        Args:
            request: The incoming HTTP request.

        Returns:
            JSON response containing suggestions.
        """
        user = request.user
        prompt = request.data.get('prompt')


        user_inputs = load_user_inputs(user)
        # user_inputs.append(prompt)
        if prompt:
            user_inputs.append(prompt)
        print(user_inputs)

        suggestions = get_suggestions(user_inputs)

        if   len(user_inputs)==0:  # First-time prompt
            suggestions = ["No previous topics found."]
            return Response({"suggestions": suggestions})

        save_user_inputs(user, suggestions)

        return Response({"suggestions": suggestions})



from .serializers import QuizSerializer ,QuestionSerializer

class ListMCQsView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]


    def get(self, request):
        user = request.user
        topic = request.query_params.get('topic', None)  
        
        if topic:
            quizzes = Quiz.objects.filter(created_by=user, title__icontains=topic)
        else:
            quizzes = Quiz.objects.filter(created_by=user)

        serializer = QuizSerializer(quizzes, many=True)
        return Response(serializer.data)


# get mcq view only 1 mcq view

class QuestionView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self,request,pk):
        try:
            question = Quiz.objects.get(pk=pk,created_by=request.user)
        except Quiz.DoesNotExist:
            return Response({"error": "MCQ not found or you do not have permission to edit it."}, status=404)

        serializer = QuizSerializer(question)
        return Response(serializer.data)

class EditMCQView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self, request, pk):
        try:
            question = Question.objects.get(pk=pk, created_by=request.user)
        except Question.DoesNotExist:
            return Response({"error": "MCQ not found or you do not have permission to access it."}, status=404)

        # Return question details
        return Response({
            "id": question.id,
            "text": question.text,
            "options": question.options,
            "correct_option": question.correct_option
        })

    def put(self, request, pk):
        try:
            question = Question.objects.get(pk=pk, created_by=request.user)
        except Question.DoesNotExist:
            return Response({"error": "MCQ not found or you do not have permission to edit it."}, status=404)

        text = request.data.get('text', question.text)
        options = request.data.get('options', question.options)
        correct_option = request.data.get('correct_option', question.correct_option)

        question.text = text
        question.options = options
        question.correct_option = correct_option
        question.save()

        return Response({"message": "MCQ updated successfully"})
    

class DeleteQuizView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    
    def delete(self ,request,pk):
        try:
            quiz = Quiz.objects.get(pk=pk,created_by=request.user)
        except Quiz.DoesNotExist:
            return Response({"error": "MCQ not found or you do not have permission to delete it"},status=404)
        
        quiz.delete()
        return Response({"message": "MCQ deleted successfully"})



class DeleteMCQView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]


    def delete(self, request, pk):
        try:
            question = Question.objects.get(pk=pk, created_by=request.user)
        except Question.DoesNotExist:
            return Response({"error": "MCQ not found or you do not have permission to delete it."}, status=404)

        question.delete()
        return Response({"message": "MCQ deleted successfully"})



class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]  # Only allows authenticated users
    authentication_classes = [JWTAuthentication]  # Uses JWT authentication

    def post(self, request):
        user = request.user  # Get the currently authenticated user directly

        # Extract the old and new passwords from the request data
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')

        # Check if the old password is correct
        if not user.check_password(old_password):
            return Response({"error": "Old password is incorrect."}, status=status.HTTP_400_BAD_REQUEST)

        # Validate that the new password is different from the old password
        if not new_password or old_password == new_password:
            return Response({"error": "New password must be provided and different from the old password."},
                            status=status.HTTP_400_BAD_REQUEST)

        # Update the password
        user.set_password(new_password)
        user.save()

        # Update session authentication hash to keep the user logged in
        update_session_auth_hash(request, user)

        return Response({"message": "Password updated successfully."}, status=status.HTTP_200_OK)
    

from django.shortcuts import get_object_or_404

class JoinQuizView(APIView):
    permission_classes = [IsAuthenticated]  
    authentication_classes = [JWTAuthentication]  

    def post(self,request):
        code = request.data.get('code')
        name = request.data.get('name')
        quiz = get_object_or_404(Quiz,code=code)

        particpent = Participant.objects.create(name=name,quiz_participent=quiz,is_active=True)
        return Response({'participant_id': particpent.id, 'quiz_id': quiz.id})

class QuestionsParticipentsView(APIView):
    permission_classes = [IsAuthenticated]  
    authentication_classes = [JWTAuthentication]  

    def get(self,request, quiz_id):
        quiz = get_object_or_404(Quiz, id=quiz_id)
        questions = quiz.questions.values('id', 'text', 'options')
        return Response({'questions': list(questions)})
    


class SubmitResponseView(APIView):
    permission_classes = [IsAuthenticated]  
    authentication_classes = [JWTAuthentication]  


    def post(self,request, quiz_id):
       
            participant_id = request.data.get('participant_id')
            responses = request.data.get('responses')  # List of question_id and selected_option

            for response in responses:
                ResponseParticipent.objects.create(
                    participant_id=participant_id,
                    question_response_id=response['question_id'],
                    select_option=response['select_option']
                )


            participant = Participant.objects.get(id=participant_id)
            participant.is_active =False
            participant.save()
            return Response({'message': 'Responses saved successfully!'})
    

class QuizResultsView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get(self,request, quiz_id):
        quiz = get_object_or_404(Quiz, id=quiz_id)
        active_participants_count = quiz.participants.filter(is_active=True).count()
        questions = quiz.questions.all()
        results = []

        for question in questions:
            options_count = {option: 0 for option in question.options}
            for response in question.responses.all():
                options_count[response.select_option] += 1

            results.append({
                'question': question.text,
                'options_count': options_count
            })

        return Response({
            'active_participants_count': active_participants_count,
            'results': results})
