import os
from dotenv import load_dotenv
from google import genai
from openai import OpenAI

load_dotenv()

def get_gemini_client():
    api_key = os.getenv("GEMINI_KEY")
    if not api_key:
        print("Error: API key doesnt exist.")
        return None
    
    return genai.Client(api_key=api_key)
# def get_ai_client():
#     api_key = os.getenv("NVIDIA_KEY")
#     base_url = "https://integrate.api.nvidia.com/v1"
    
#     if not api_key:
#         print("Error: NVIDIA_API_KEY not found!")
#         return None
        
#     return OpenAI(base_url=base_url, api_key=api_key)