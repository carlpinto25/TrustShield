"""
LangChain agent wiring: registers all tools and invokes them per modality.
Returns a structured AnalysisResult.
"""
import json
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage, SystemMessage
from app.config import GEMINI_API_KEY, GEMINI_MODEL, GEMINI_MODEL_FALLBACKS
from app.models import AnalysisResult


def _risk_level(score: float) -> str:
    if score < 0.3:
        return "LOW"
    elif score < 0.6:
        return "MEDIUM"
    elif score < 0.85:
        return "HIGH"
    return "CRITICAL"


def invoke_with_fallback(messages: list) -> str:
    """Try GEMINI_MODEL then each fallback until one succeeds."""
    models_to_try = [GEMINI_MODEL] + GEMINI_MODEL_FALLBACKS
    last_err = None
    for model_name in models_to_try:
        try:
            llm = ChatGoogleGenerativeAI(
                model=model_name,
                google_api_key=GEMINI_API_KEY,
                temperature=0.1,
            )
            return llm.invoke(messages).content
        except Exception as e:
            last_err = e
            if "429" not in str(e) and "RESOURCE_EXHAUSTED" not in str(e):
                raise
    raise RuntimeError(f"All Gemini models exhausted. Last error: {last_err}")


def run_text_agent(text: str, url_flags: dict) -> AnalysisResult:
    system = (
        "You are a cybersecurity expert specializing in phishing detection. "
        "Analyse the provided text for phishing indicators: urgency language, "
        "impersonation, social engineering, suspicious URLs, credential harvesting. "
        "Respond ONLY with valid JSON matching this schema: "
        '{"risk_score": <float 0-1>, "threat_types": [<strings>], "explanation": <string>}'
    )
    prompt = f"TEXT TO ANALYSE:\n{text}\n\nURL SCAN RESULTS:\n{json.dumps(url_flags)}"
    raw = invoke_with_fallback([SystemMessage(content=system), HumanMessage(content=prompt)])
    raw = raw.strip().strip("```json").strip("```").strip()
    data = json.loads(raw)
    score = float(data["risk_score"])
    return AnalysisResult(
        risk_score=score,
        risk_level=_risk_level(score),
        threat_types=data.get("threat_types", []),
        explanation=data.get("explanation", ""),
        tool_outputs={"gemini_text": data, "url_scan": url_flags},
    )


def run_image_agent(hf_result: dict, gemini_result: dict) -> AnalysisResult:
    hf_score = hf_result.get("deepfake_score", 0.0)
    gemini_score = gemini_result.get("risk_score", 0.0)
    combined = round((hf_score * 0.5) + (gemini_score * 0.5), 3)
    threat_types = list(
        set(hf_result.get("threat_types", []) + gemini_result.get("threat_types", []))
    )
    explanation = (
        f"HuggingFace deepfake model: {hf_result.get('label', 'N/A')} "
        f"(confidence {hf_score:.2f}). "
        f"Gemini vision analysis: {gemini_result.get('explanation', '')}"
    )
    return AnalysisResult(
        risk_score=combined,
        risk_level=_risk_level(combined),
        threat_types=threat_types,
        explanation=explanation,
        tool_outputs={"hf_deepfake": hf_result, "gemini_vision": gemini_result},
    )


def run_video_agent(gemini_result: dict, frame_scores: list[float]) -> AnalysisResult:
    gemini_score = gemini_result.get("risk_score", 0.0)
    avg_frame = sum(frame_scores) / len(frame_scores) if frame_scores else 0.0
    combined = round((gemini_score * 0.6) + (avg_frame * 0.4), 3)
    explanation = (
        f"Gemini video analysis score: {gemini_score:.2f}. "
        f"Frame-level deepfake average: {avg_frame:.2f} over {len(frame_scores)} frames. "
        f"{gemini_result.get('explanation', '')}"
    )
    return AnalysisResult(
        risk_score=combined,
        risk_level=_risk_level(combined),
        threat_types=gemini_result.get("threat_types", ["deepfake_video"]),
        explanation=explanation,
        tool_outputs={"gemini_video": gemini_result, "frame_scores": frame_scores},
    )


def run_audio_agent(hf_result: dict, gemini_result: dict) -> AnalysisResult:
    hf_score = hf_result.get("deepfake_score", 0.0)
    gemini_score = gemini_result.get("risk_score", 0.0)
    combined = round((hf_score * 0.5) + (gemini_score * 0.5), 3)
    threat_types = list(
        set(hf_result.get("threat_types", []) + gemini_result.get("threat_types", []))
    )
    explanation = (
        f"HuggingFace audio deepfake model: {hf_result.get('label', 'N/A')} "
        f"(confidence {hf_score:.2f}). "
        f"Gemini audio analysis: {gemini_result.get('explanation', '')}"
    )
    return AnalysisResult(
        risk_score=combined,
        risk_level=_risk_level(combined),
        threat_types=threat_types,
        explanation=explanation,
        tool_outputs={"hf_audio": hf_result, "gemini_audio": gemini_result},
    )
