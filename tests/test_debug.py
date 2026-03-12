import os
import sys
import json

# Add the project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.config import GEMINI_API_KEY, GEMINI_MODEL
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage, SystemMessage
from google.genai import types

def test_debug():
    text = "Is the company 'DeepSeek' currently in the news for anything related to AI or data privacy? Could this be a scam related to them?"
    system = "You are a phishing analyst. Reply ONLY with valid JSON: {'risk_score': 0.0, 'threat_types': [], 'explanation': 'test'}"
    
    messages = [SystemMessage(content=system), HumanMessage(content=text)]
    search_tool = types.Tool(google_search=types.GoogleSearch())
    
    # Try passing model_kwargs={"response_format": {"type": "json_object"}} or similar if supported
    # In ChatGoogleGenerativeAI, it is sometimes supported. Let's try without it first but with a stronger prompt.
    system_stronger = (
        "You are an automated JSON API. You must return your analysis strictly as a JSON object, and absolutely no other text. "
        "Use this exact schema:\n"
        "{\n"
        '  "risk_score": 0.5,\n'
        '  "threat_types": [],\n'
        '  "explanation": "..."\n'
        "}\n"
        "DO NOT write markdown or explanations outside the JSON block."
    )
    
    messages = [SystemMessage(content=system_stronger), HumanMessage(content=text)]
    llm = ChatGoogleGenerativeAI(model=GEMINI_MODEL, google_api_key=GEMINI_API_KEY, temperature=0.1)
    
    print("Invoking with tools and stronger prompt...")
    resp_with_tools = llm.invoke(messages, tools=[search_tool])
    print(f"Content: {resp_with_tools.content}\n")
    
test_debug()
