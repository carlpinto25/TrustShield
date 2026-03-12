import os
import json
import tempfile
import time
import cv2
from google import genai
from google.genai import types
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage, SystemMessage
from app.config import GEMINI_API_KEY, GEMINI_MODEL
from app.tools.image_tools import hf_detect_image_deepfake

client = genai.Client(api_key=GEMINI_API_KEY)


def sample_frames(video_bytes: bytes, n_frames: int = 8) -> list[bytes]:
    with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as tmp:
        tmp.write(video_bytes)
        tmp_path = tmp.name
    frames = []
    try:
        cap = cv2.VideoCapture(tmp_path)
        total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        step = max(1, total // n_frames)
        for i in range(n_frames):
            cap.set(cv2.CAP_PROP_POS_FRAMES, i * step)
            ret, frame = cap.read()
            if ret:
                _, buf = cv2.imencode(".jpg", frame)
                frames.append(buf.tobytes())
        cap.release()
    finally:
        os.unlink(tmp_path)
    return frames


def gemini_analyze_video(video_bytes: bytes, mime_type: str = "video/mp4") -> dict:
    with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as tmp:
        tmp.write(video_bytes)
        tmp_path = tmp.name
    try:
        uploaded = client.files.upload(file=tmp_path, config=types.UploadFileConfig(mime_type=mime_type))
        while uploaded.state.name == "PROCESSING":
            time.sleep(2)
            uploaded = client.files.get(name=uploaded.name)

        system_prompt = (
            "You are a deepfake and media manipulation expert. Analyse this video for: "
            "AI-generated faces, lip-sync inconsistencies, unnatural blinking, "
            "visual artefacts, lighting inconsistencies, and audio-visual mismatch. "
            "Use the Google Search tool to verify any claims, news, or context if needed. "
            "Reply ONLY with valid JSON: "
            '{"risk_score": <float 0-1>, "threat_types": [<strings>], "explanation": <string>}'
        )
        from app.tools.retry_utils import execute_with_retry
        
        # Enable Google Search Grounding
        tool = types.Tool(google_search=types.GoogleSearch())
        config = types.GenerateContentConfig(tools=[tool])
        
        response = execute_with_retry(
            lambda: client.models.generate_content(
                model=GEMINI_MODEL,
                contents=[system_prompt, uploaded],
                config=config
            )
        )
        raw = response.text.strip().strip("```json").strip("```").strip()
        return json.loads(raw)
    except Exception as e:
        return {"risk_score": 0.0, "threat_types": [], "explanation": f"Error: {e}"}
    finally:
        os.unlink(tmp_path)


def score_video_frames(video_bytes: bytes) -> list[float]:
    frames = sample_frames(video_bytes)
    scores = []
    for frame_bytes in frames:
        result = hf_detect_image_deepfake(frame_bytes, mime_type="image/jpeg")
        scores.append(result.get("deepfake_score", 0.0))
    return scores
