from fastapi import APIRouter, UploadFile, File, HTTPException
from app.models import AnalysisResult
from app.tools.image_tools import hf_detect_image_deepfake, gemini_analyze_image
from app.agent import run_image_agent

router = APIRouter()


@router.post("/image", response_model=AnalysisResult)
async def analyze_image(file: UploadFile = File(...)):
    allowed = {"image/jpeg", "image/png", "image/webp", "image/gif"}
    if file.content_type not in allowed:
        raise HTTPException(status_code=400, detail=f"Unsupported image type: {file.content_type}")
    try:
        image_bytes = await file.read()
        hf_result = hf_detect_image_deepfake(image_bytes, mime_type=file.content_type)
        gemini_result = gemini_analyze_image(image_bytes, mime_type=file.content_type)
        return run_image_agent(hf_result, gemini_result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
