from fastapi import APIRouter, UploadFile, File, HTTPException
from app.models import AnalysisResult
from app.tools.video_tools import gemini_analyze_video, score_video_frames
from app.agent import run_video_agent

router = APIRouter()


@router.post("/video", response_model=AnalysisResult)
async def analyze_video(file: UploadFile = File(...)):
    allowed = {"video/mp4", "video/mpeg", "video/webm", "video/quicktime"}
    if file.content_type not in allowed:
        raise HTTPException(status_code=400, detail=f"Unsupported video type: {file.content_type}")
    try:
        video_bytes = await file.read()
        gemini_result = gemini_analyze_video(video_bytes, mime_type=file.content_type)
        frame_scores = score_video_frames(video_bytes)
        return run_video_agent(gemini_result, frame_scores)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
