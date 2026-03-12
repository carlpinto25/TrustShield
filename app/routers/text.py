from fastapi import APIRouter, HTTPException
from app.models import TextRequest, AnalysisResult
from app.tools.text_tools import analyze_urls_in_text, gemini_analyze_text
from app.agent import run_text_agent

router = APIRouter()


@router.post("/text", response_model=AnalysisResult)
async def analyze_text(request: TextRequest):
    try:
        url_flags = analyze_urls_in_text(request.text)
        gemini_data = gemini_analyze_text(request.text)
        return run_text_agent(request.text, url_flags)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
