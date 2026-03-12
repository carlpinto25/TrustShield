"""
Image tools:
- HuggingFace Inference API for deepfake image detection
- Gemini Vision for phishing screenshot / fake document analysis
"""
import json
import base64
import tempfile
import os
from huggingface_hub import InferenceClient
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage, SystemMessage
from app.config import GEMINI_API_KEY, GEMINI_MODEL, GEMINI_MODEL_FALLBACKS, HF_IMAGE_MODEL
from transformers import pipeline

# Global pipeline instance to load model once at startup (or first use)
_image_classifier = None

def get_image_classifier():
    global _image_classifier
    if _image_classifier is None:
        # Load the local model that was downloaded by download_models.py
        _image_classifier = pipeline("image-classification", model=HF_IMAGE_MODEL)
    return _image_classifier



def hf_detect_image_deepfake(image_bytes: bytes, mime_type: str = "image/jpeg") -> dict:
    from PIL import Image
    import io

    try:
        # Open image using PIL
        image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        
        # Get the initialized pipeline
        classifier = get_image_classifier()
        
        # Run inference locally
        results = classifier(image)
        
        # Transformers pipeline returns a list of dicts like: [{'label': 'real', 'score': 0.9}, ...]
        label_map = {r['label'].lower(): r['score'] for r in results}
        fake_score = label_map.get("fake", label_map.get("deepfake", 0.0))
        label = "FAKE" if fake_score > 0.5 else "REAL"
        
        return {
            "label": label,
            "deepfake_score": round(fake_score, 4),
            "threat_types": ["deepfake_image"] if fake_score > 0.5 else [],
            "raw": [{"label": r['label'], "score": r['score']} for r in results],
        }
    except Exception as e:
        return {"label": "ERROR", "deepfake_score": 0.0, "threat_types": [], "error": str(e)}



def gemini_analyze_image(image_bytes: bytes, mime_type: str = "image/jpeg") -> dict:
    b64 = base64.b64encode(image_bytes).decode()
    system = (
        "You are an automated cybersecurity image analyst API. Examine the image for: "
        "fake login pages, phishing screenshots, fake documents, impersonated brands, "
        "deepfake or AI-generated faces/content. "
        "Use the Google Search tool to verify any claims, news, or context if needed. "
        "You MUST return your analysis strictly as a JSON object and absolutely nothing else. "
        '{"risk_score": <float 0-1>, "threat_types": [<strings>], "explanation": <string>}'
    )
    message = HumanMessage(
        content=[
            {"type": "text", "text": system},
            {"type": "image_url", "image_url": {"url": f"data:{mime_type};base64,{b64}"}},
        ]
    )
    from app.tools.retry_utils import execute_with_retry
    from google.genai import types
    search_tool = types.Tool(google_search=types.GoogleSearch())
    
    for model in [GEMINI_MODEL] + GEMINI_MODEL_FALLBACKS:
        try:
            resp = execute_with_retry(
                lambda m=model: ChatGoogleGenerativeAI(
                    model=m, 
                    google_api_key=GEMINI_API_KEY, 
                    temperature=0.1
                ).invoke([message], tools=[search_tool])
            )
            raw = resp.content
            if not isinstance(raw, str):
                raw = str(raw)
                
            raw = raw.strip().strip("```json").strip("```").strip()
            return json.loads(raw)
        except Exception as e:
            if "429" not in str(e) and "RESOURCE_EXHAUSTED" not in str(e):
                raise
    return {"risk_score": 0.0, "threat_types": [], "explanation": "Gemini quota exhausted for all models"}
