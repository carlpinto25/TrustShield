"""
Audio tools:
- HuggingFace Inference API for deepfake/AI-voice detection
- Gemini for voice-scam content analysis
"""
import json
import base64
import tempfile
import os
from huggingface_hub import InferenceClient
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage, SystemMessage
from app.config import GEMINI_API_KEY, GEMINI_MODEL, GEMINI_MODEL_FALLBACKS, HF_AUDIO_MODEL
from transformers import pipeline

# Global pipeline instance to load model once at startup (or first use)
_audio_classifier = None

def get_audio_classifier():
    global _audio_classifier
    if _audio_classifier is None:
        # Load the local model that was downloaded by download_models.py
        _audio_classifier = pipeline("audio-classification", model=HF_AUDIO_MODEL)
    return _audio_classifier


def hf_detect_audio_deepfake(audio_bytes: bytes) -> dict:
    import io
    import soundfile as sf
    import numpy as np

    try:
        # Read the audio bytes directly into a numpy array (skipping the disk write)
        # pipeline("audio-classification") expects either a file path or a raw waveform array
        audio_data, sample_rate = sf.read(io.BytesIO(audio_bytes))

        # sf.read might return stereo (2D array), convert to mono if necessary
        if len(audio_data.shape) > 1:
            audio_data = audio_data.mean(axis=1)
            
        # Get the initialized pipeline
        classifier = get_audio_classifier()
        
        # We must provide the correct sampling rate if passing raw arrays
        # The pipeline usually expects 16kHz for deepfake models, 
        # but passing it as a dict {raw: array, sampling_rate: sr} is supported by HF pipelines
        results = classifier({"raw": audio_data, "sampling_rate": sample_rate})
        
        # Transformers pipeline returns a list of dicts like: [{'label': 'real', 'score': 0.9}, ...]
        label_map = {r['label'].lower(): r['score'] for r in results}
        fake_score = label_map.get("fake", label_map.get("spoof", label_map.get("ai-generated", 0.0)))
        label = "FAKE" if fake_score > 0.5 else "REAL"
        
        return {
            "label": label,
            "deepfake_score": round(fake_score, 4),
            "threat_types": ["deepfake_audio", "ai_voice"] if fake_score > 0.5 else [],
            "raw": [{"label": r['label'], "score": r['score']} for r in results],
        }
    except Exception as e:
        return {"label": "ERROR", "deepfake_score": 0.0, "threat_types": [], "error": str(e)}



def gemini_analyze_audio(audio_bytes: bytes, mime_type: str = "audio/wav") -> dict:
    b64 = base64.b64encode(audio_bytes).decode()
    system = (
        "You are an automated voice fraud and deepfake audio expert API. Analyse this audio for: "
        "AI-generated voice patterns, robotic/synthetic speech artifacts, voice cloning indicators, "
        "scam scripts (fake tech support, fake bank calls, urgent threats). "
        "Use the Google Search tool to verify any claims, news, or context if needed. "
        "You MUST return your analysis strictly as a JSON object and absolutely nothing else. "
        '{"risk_score": <float 0-1>, "threat_types": [<strings>], "explanation": <string>}'
    )
    message = HumanMessage(
        content=[
            {"type": "text", "text": system},
            {"type": "media", "data": b64, "mime_type": mime_type},
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
