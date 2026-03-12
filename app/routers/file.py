from fastapi import APIRouter, HTTPException, UploadFile, File
from app.models import AnalysisResult
from app.tools.virustotal_tools import scan_file_virustotal

router = APIRouter()

def _risk_level(score: float) -> str:
    if score < 0.3:
        return "LOW"
    elif score < 0.6:
        return "MEDIUM"
    elif score < 0.85:
        return "HIGH"
    return "CRITICAL"

@router.post("/file", response_model=AnalysisResult)
async def analyze_file(file: UploadFile = File(...)):
    try:
        content = await file.read()
        vt_result = scan_file_virustotal(content, file.filename)
        
        # Calculate a simple risk score based on VT malicious count
        # 0 malicious = 0 score, 5+ malicious = 1.0 score
        malicious = vt_result.get("malicious", 0)
        risk_score = min(malicious / 5.0, 1.0)
        
        threat_types = []
        if malicious > 0:
            threat_types.append("malicious_file")
        if vt_result.get("suspicious", 0) > 0:
            threat_types.append("suspicious_file")
            
        explanation = f"VirusTotal analysis for {file.filename}: {malicious} malicious detections."
        if "status" in vt_result:
            explanation = vt_result["message"]

        return AnalysisResult(
            risk_score=risk_score,
            risk_level=_risk_level(risk_score),
            threat_types=threat_types,
            explanation=explanation,
            tool_outputs={"virustotal_file": vt_result}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        await file.close()
