from fastapi import APIRouter, UploadFile, File, HTTPException
from app.models import AnalysisResult
from app.tools.audio_tools import hf_detect_audio_deepfake, gemini_analyze_audio
from app.agent import run_audio_agent

router = APIRouter()


@router.post("/audio", response_model=AnalysisResult)
async def analyze_audio(file: UploadFile = File(...)):
    allowed = {"audio/wav", "audio/mpeg", "audio/mp3", "audio/ogg", "audio/x-wav"}
    if file.content_type not in allowed:
        raise HTTPException(status_code=400, detail=f"Unsupported audio type: {file.content_type}")
    try:
        audio_bytes = await file.read()
        hf_result = hf_detect_audio_deepfake(audio_bytes)
        gemini_result = gemini_analyze_audio(audio_bytes, mime_type=file.content_type)
        return run_audio_agent(hf_result, gemini_result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
