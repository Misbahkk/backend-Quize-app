# generate_quiz.py
import os
import json
import google.generativeai as genai
# from dotenv import load_dotenv
import threading
from django.conf import settings
from .models import Suggestion

# Load environment variables


# Configure the Google Generative AI API

genai.configure(api_key=settings.GEMINI_API_KEY)

# Set up generation configuration
generation_config = {
    "temperature": 0.6,
    "top_p": 0.95,
    "top_k": 40,
    "max_output_tokens": 600,
    "response_mime_type": "text/plain",
}

lock = threading.Lock()

# Initialize the model
model = genai.GenerativeModel(
    model_name="gemini-1.5-flash",
    generation_config=generation_config,
)

# Load and Save User Inputs
def load_user_inputs(user):
    """  Load user input with a jason file """

    # return Suggestion.objects.filter(created_by=user).values_list('topic', flat=True)
    return list(Suggestion.objects.filter(created_by=user).values_list('topic', flat=True))

# def save_user_inputs(user_inputs):
#     with lock:
#         with open("user_inputs.json", "a") as file:
#             json.dump(user_inputs or [], file,indent=4)

def save_user_inputs(user, suggestions):
    """Save new suggestions to the database."""
    for suggestion in suggestions:
        Suggestion.objects.create(topic=suggestion, created_by=user)

# Generate Quiz Questions
def generate_quiz_questions(topic):
    """
    Generate quiz questions based on the given topic using Google Generative AI.

    Args:
        topic (str): The topic to generate quiz questions for.

    Returns:
        list: A list of generated quiz questions.
    """
    try: 
        chat_session = model.start_chat(history=[])
        response = chat_session.send_message(f"Generate a quiz with 5 MCQ questions on '{topic}'. Format each question as: Question | Option A | Option B | Option C | Option B | Correct Option (A/B/C/D) write that only option not like correct option (A/B/C/D)")
        # return response.text.strip().split('\n')
        print("Quiz generation response:", response.text) 
        questions = []
        for line in response.text.strip().split('\n'):
            parts = line.split('|')  # Assuming '|' separates question, options, and correct answer
            if len(parts) >= 7:
                question_text = parts[1].strip()
                option_a = parts[2].strip()
                option_b = parts[3].strip()
                option_c = parts[4].strip()
                option_d = parts[5].strip()
                correct_option = parts[6].strip().upper()
                if correct_option not in ['A', 'B','C','D']:
                    correct_option = 'A'  # Default if incorrect
                questions.append({
                    "text": question_text,
                    "options": {"A": option_a, "B": option_b,"C": option_c,"D": option_d},
                    "correct_option": correct_option,
                })
                # questions.append({
                #     "text": parts[0].strip(),
                #     "options": {"A": parts[1].strip(), "B": parts[2].strip()},  # Add more as necessary
                #     "correct_option": "A",  # Default correct option
                # })
        return questions
    except Exception as e:
        print(f"Error genrating Quiz Q's {e}")
        return []

# Generate Suggestions
def get_suggestions(user_inputs):
    """
    Generate topic suggestions based on user inputs.

    Args:
        user_inputs (list): List of previous user inputs.

    Returns:
        list: Suggested topics.
    """
    try:
        if not user_inputs:
            return ["No previous topics found."]
        
        # previous_topics = [entry['text'] for entry in user_inputs]
        combined_input = ". ".join(user_inputs)
        # print("Combined input for suggestions:", combined_input)
            
        chat_session = model.start_chat(history=[])
        response = chat_session.send_message(f"Suggest only simple 6 one linetopics based on: {combined_input}")
        print("Chat model response:", response.text)  # Debugging log
        return response.text.strip().split('\n')[:6]
    except Exception as e:
        print(f"Error generating suggestions {e}")
        return []




def extract_line(text_line, ignore_keyword):
    """
    Extract meaningful lines from a list of text lines by ignoring specified keywords.

    Args:
        text_lines (list): List of text lines.
        ignore_keywords (list): Keywords to ignore.

    Returns:
        list: Filtered lines.
    """
    return [
        line.strip() for line in text_line if not any(keyword in line for keyword in ignore_keyword) and line.strip()
    ]



# def extract_mcqs(text_dict):
#     questions = []
    
#     for line in text_dict:
#         # Skip headers, instructions, and blank lines
#         if "##" in line or "Instructions" in line or line.strip() == "":
#             continue
#         # Clean line and append it to the questions list
#         questions.append(line.strip())

#     return questions 

# def extract_suggested_qs(text_dict):
#     suggetion =[]
#     for line in text_dict:
#         # Skip headers, instructions, and blank lines
#         if "##" in line or "Here are 6 one-line" in line or line.strip() == "":
#             continue
#         # Clean line and append it to the questions list
#         suggetion.append(line.strip())
    
#     return suggetion 
