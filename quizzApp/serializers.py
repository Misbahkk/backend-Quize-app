# # serializers.py
from rest_framework import serializers
from .models import User ,Question,Quiz

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id','name','email','password','role']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        password = validated_data.pop('password',None)
        isinstance = self.Meta.model(**validated_data)
        if password is not None:
            isinstance.set_password(password)
        isinstance.save()
        return isinstance
    


class QuestionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Question
        fields = ['id', 'text', 'options', 'correct_option', 'created_by']

class QuizSerializer(serializers.ModelSerializer):
    questions = QuestionSerializer(many=True, read_only=True)  # Nested serializer for related questions

    class Meta:
        model = Quiz
        fields = ['id', 'title', 'description', 'course_name', 'subject', 'questions']