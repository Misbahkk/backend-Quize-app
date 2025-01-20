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
    

class UpdateUserView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    def get(self, request, *args, **kwargs):
        user = request.user  # Authenticated user
        serializer = UserSerializer(user)  # Serialize user data
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    
    def put(self, request, *args, **kwargs):
        user = request.user  # Authenticated user
        serializer = UserSerializer(user, data=request.data, partial=True)  # `partial=True` allows partial updates
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




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
        Handle POST requests to generate a quiz 

        Args:
            request: The incoming HTTP request.

        Returns:
            JSON response containing quiz questions.
        """
        print("Request body:", request.body)  # Raw body
        print("Request data:", request.data)  # Parsed data
        # Prompt input
        user = request.user
        prompt = request.data.get('prompt')
        
        if not prompt:
            return Response({"error": "Prompt is required"}, status=400)

        

        quiz_questions = generate_quiz_questions(prompt)
        quize_code = generate_quiz_code()
        
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
        
        # Send response
        return Response({
            "quiz_id": quiz.id,
            "quiz_code": quize_code,
            "quiz_questions": mcqs,
           
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


class EditQuizView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def put(self, request, pk):
        try:
            quiz = Quiz.objects.get(pk=pk, created_by=request.user)
        except Quiz.DoesNotExist:
            return Response({"error": "Quiz not found or you do not have permission to edit it."}, status=404)

        data = request.data

        quiz.title = data.get('title', quiz.title)
        quiz.description = data.get('description', quiz.description)
        
        quiz.course_name = data.get('course_name', quiz.course_name)
        quiz.subject = data.get('subject', quiz.subject)

        quiz.save()

        return Response({"message": "Quiz updated successfully"})


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
    

# TODO: Ya pura ek quize delete kr da ga
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


# TODO: ya pura ek question delete kare ga
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
     

    def post(self,request):
        code = request.data.get('code')
        name = request.data.get('name')
        email = request.data.get('email')
        quiz = get_object_or_404(Quiz,code=code)

        existing_participant = Participant.objects.filter(email=email, quiz_participent=quiz, is_active=True).first()
        if existing_participant:
            return Response({'error': 'Participant already joined this quiz'}, status=400)

        particpent = Participant.objects.create(name=name,email=email,quiz_participent=quiz,is_active=True)
        return Response({'participant_id': particpent.id, 'quiz_id': quiz.id})

class QuestionsParticipentsView(APIView):
    

    def get(self,request, quiz_id):
        participant_id = request.query_params.get('participant_id')
        if not participant_id:
            return Response({'error': 'Participant ID is required'}, status=400)
        
        try:
            participant = Participant.objects.get(id=participant_id, quiz_participent_id=quiz_id)
        except Participant.DoesNotExist:
            return Response({'error': 'Participant not authorized for this quiz'}, status=403)

        
        if not participant.is_active:
            return Response({"message":"you have alredy join the quiz thank you "})
        
        # Only fetch questions if the participant is valid
        quiz = participant.quiz_participent
        questions = quiz.questions.values('id', 'text', 'options')
        return Response({'questions': list(questions)})
    

class SubmitResponseView(APIView):
    def post(self,request, quiz_id):
       
            participant_id = request.data.get('participant_id')
            responses = request.data.get('responses')  # List of question_id and selected_option
            try:
                participant = Participant.objects.get(id=participant_id, quiz_participent_id=quiz_id)
            except Participant.DoesNotExist:
                return Response({'error': 'Participant not authorized for this quiz'}, status=403)


            for response in responses:
                ResponseParticipent.objects.create(
                    participant_id=participant_id,
                    question_response_id=response['question_id'],
                    select_option=response['select_option']
                )          
            total_marks , status ,passing_marks= calculate_marks(participant,quiz_id)
            if total_marks>=passing_marks:
                participant.passed_quiz_count+=1
               
            else:
                participant.failed_quiz_count+=1
            participant.total_attempts =+1
            participant.is_active =False
            participant.save()
            return Response({'message':'Responses saved successfully!'})
    

# class SubmitResponseView(APIView):
#     def post(self, request, quiz_id):
#         participant_id = request.data.get('participant_id')
#         question_id = request.data.get('question_id')
#         selected_option = request.data.get('selected_option')

#         # Validate participant existence
#         try:
#             participant = Participant.objects.get(id=participant_id, quiz_participent_id=quiz_id)
#         except Participant.DoesNotExist:
#             return Response({'error': 'Participant not authorized for this quiz'}, status=403)

#         # Create the response for the selected question and option
#         try:
#             ResponseParticipent.objects.create(
#                 participant_id=participant_id,
#                 question_response_id=question_id,
#                 select_option=selected_option
#             )
#         except Exception as e:
#             return Response({'error': str(e)}, status=400)

#         # Calculate the participant's marks and status
#         total_marks, status, passing_marks = calculate_marks(participant, quiz_id)

#          # Check if the quiz is finished
#         completed_responses = ResponseParticipent.objects.filter(participant_id=participant_id, quiz_participent_id=quiz_id)
#         total_questions = Quiz.objects.get(id=quiz_id).questions.count()  # Assuming you have a relation between quiz and questions

#         # Update participant status after quiz completion
#         if completed_responses.count() == total_questions:
#             participant.is_active = False
#             participant.total_attempts += 1


#         # Update participant stats based on their performance
#         if total_marks >= passing_marks:
#             participant.passed_quiz_count += 1
#         else:
#             participant.failed_quiz_count += 1

        
#           # Disable participant after quiz submission
#         participant.save()

#         return Response({'message': 'Response saved successfully!'}, status=200)

# class QuizLivePollingView(APIView):
#     permission_classes = [IsAuthenticated]
#     authentication_classes = [JWTAuthentication]

#     def get(self, request, quiz_id):
#         quiz = get_object_or_404(Quiz, id=quiz_id)
#         active_participants_count = quiz.participants.filter(is_active=True).count()
#         questions = quiz.questions.all()
#         results = []

#         for question in questions:
#             options_count = {option: 0 for option in question.options}
#             for response in question.responses.all():
#                 options_count[response.select_option] += 1

#             results.append({
#                 'options_count': options_count
#             })

#         return Response({
#             'active_participants_count': active_participants_count,
#             'results': results
#         })

#     def post(self, request, quiz_id):
#         # Retrieve participant_id, question_id, and selected_option from the request body
#         participant_id = request.data.get('participant_id')
#         question_id = request.data.get('question_id')
#         selected_option = request.data.get('selected_option')

#         # Validate if the data is present
#         if not all([participant_id, question_id, selected_option]):
#             return Response({'error': 'Missing required fields.'}, status=400)

#         # Get the quiz and the question
#         quiz = get_object_or_404(Quiz, id=quiz_id)
#         question = get_object_or_404(Question, id=question_id)

#         # Record the participant's response
#         ResponseParticipent.objects.create(
#             participant_id=participant_id,
#             question=question,
#             select_option=selected_option
#         )

#         # Optionally, you can return a success message
#         return Response({'message': 'Response recorded successfully.'}, status=201)

class QuizLivePollingView(APIView):
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
                # 'question': question.text,
                'options_count': options_count
            })

        return Response({
            'active_participants_count': active_participants_count,
            'results': results})


# from asgiref.sync import async_to_sync
# from channels.layers import get_channel_layer

# class QuizLivePollingView(APIView):
#     # Existing code...
#     permission_classes = [IsAuthenticated]
#     authentication_classes = [JWTAuthentication]

#     def post(self, request, quiz_id):
#         user = request.user
#         quiz = get_object_or_404(Quiz, id=quiz_id)
#         question = quiz.questions.get(id=request.data['question_id'])
#         selected_option = request.data['selected_option']

#         # Update response count
#         question.responses.create(user=user, select_option=selected_option)

#         # Send live update
#         options_count = {option: 0 for option in question.options}
#         for response in question.responses.all():
#             options_count[response.select_option] += 1

#         channel_layer = get_channel_layer()
#         async_to_sync(channel_layer.group_send)(
#             f'quiz_{quiz_id}',
#             {
#                 'type': 'poll_update',
#                 'message': {
#                     'active_participants_count': quiz.participants.filter(is_active=True).count(),
#                     'results': [{
#                         'options_count': options_count
#                     }]
#                 }
#             }
#         )

#         return Response({'message': 'Vote recorded successfully.'})


class quiz_result(APIView):
    permission_classes = [IsAuthenticated]  
    authentication_classes = [JWTAuthentication]  

    def get(self,request, quiz_id):
        # Specific quiz filter
        quiz = get_object_or_404(Quiz, id=quiz_id)

        total_question = quiz.total_questions
        max_markx = total_question*10
        # Quiz ke participants fetch karna
        participants = Participant.objects.filter(quiz_participent=quiz)

        results = []

        # Har participant ka data fetch karna
        for participant in participants:
            # ResponseParticipent se total marks calculate karna
            total_marks,status ,passing_markx= calculate_marks(participant,quiz_id)
           


            results.append({
                "name": participant.name,
                "marks": f"{total_marks}/{max_markx}",  # Assuming total marks are out of 100
                "status": status
            })

        # Response bhejna
        return Response({
            "quiz_name": quiz.title,
            "results": results
        })


def calculate_marks(participant,quiz_id):
    responses = ResponseParticipent.objects.filter(participant=participant)
    quiz = get_object_or_404(Quiz, id=quiz_id)
    correct_responses = 0
    total_question = quiz.total_questions
    max_markx = total_question*10
    passing_marks = max_markx/2


    for response in responses:
        # Assume every correct answer gives 10 marks
        if response.select_option == response.question_response.correct_option:
            correct_responses += 1
    total_marks =correct_responses * 10
    status = "Pass" if total_marks >= passing_marks else "Fail"

    # Example: If each question carries 10 marks
    return total_marks,status ,passing_marks


    

from django.db.models import Count,Q
class UserQuestionReport(APIView):
    permission_classes = [IsAuthenticated]  
    authentication_classes = [JWTAuthentication]  

    def get(selg,request):
        user = request.user
        # Get all questions created by the specific user
        user_questions = Question.objects.filter(created_by_id=user)
        
        # Total questions created by the user
        total_questions = user_questions.count()
        
        # Group questions by text to find duplicates
        question_counts = user_questions.values('text').annotate(count=Count('id'))
        
        # Calculate unique and repeated questions
        unique_questions = sum(1 for q in question_counts if q['count'] == 1)
        repeated_questions = total_questions - unique_questions
        
        # Prepare data for response
        data = {
            'total_questions': total_questions,
            'unique_questions': unique_questions,
            'repeated_questions': repeated_questions,
        }
        return Response(data)





from rest_framework import status
from django.db.models import Count, Q


class UserQuizAnalysis(APIView):
    permission_classes = [IsAuthenticated]  
    authentication_classes = [JWTAuthentication]  

    def get(self, request):
        # Get quizzes created by the user
        user = request.user
        quizzes = Quiz.objects.filter(created_by_id=user)

        # Get participants for these quizzes
        participants = Participant.objects.filter(quiz_participent__in=quizzes)

        # Annotate participants with their pass/fail counts dynamically
        analysis = participants.annotate(
            pass_count=Count('quiz_participent', filter=Q(passed_quiz_count__gte=1)),
            fail_count=Count('quiz_participent', filter=Q(failed_quiz_count__gte=1))
        ).values('name', 'email', 'total_attempts', 'pass_count', 'fail_count')

        return Response(analysis)



        



class ParticipantResultAPIView(APIView):
    def get(self, request, participant_id):
        try:
            participant = Participant.objects.get(id=participant_id)
            responses = ResponseParticipent.objects.filter(participant=participant)

            total_questions = responses.count()
            correct_answers = responses.filter(is_correct=True).count()
            wrong_answers = total_questions - correct_answers
            pass_criteria = 5  # Pass criteria (change as required)
            passed = correct_answers >= pass_criteria

            result = {
                "name": participant.name,
                "total_questions": total_questions,
                "correct_answers": correct_answers,
                "wrong_answers": wrong_answers,
                "passed": passed,
                "pass_criteria": pass_criteria,
            }
            return Response(result)
        except Participant.DoesNotExist:
            return Response({"error": "Participant not found"}, status=404)