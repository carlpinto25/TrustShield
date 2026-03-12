"""
Text tools: phishing text analysis via Gemini + URL extraction/scoring.
"""
import re
import json
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage, SystemMessage
from app.config import GEMINI_API_KEY, GEMINI_MODEL, GEMINI_MODEL_FALLBACKS

_SUSPICIOUS_TLD = re.compile(
    r"https?://[^\s\"'<>]+", re.IGNORECASE
)
_BAD_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".loan", ".work"}


def extract_urls(text: str) -> list[str]:
    return _SUSPICIOUS_TLD.findall(text)


def score_url(url: str, use_vt: bool = True) -> dict:
    from urllib.parse import urlparse
    from app.tools.virustotal_tools import scan_url_virustotal
    
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    flags = []
    is_suspicious = False

    for tld in _BAD_TLDS:
        if domain.endswith(tld):
            flags.append(f"suspicious_tld:{tld}")
            is_suspicious = True

    brand_impersonations = ["paypal", "amazon", "google", "microsoft", "apple", "bank", "secure", "login", "verify"]
    for brand in brand_impersonations:
        if brand in domain and not domain.startswith(brand + "."):
            flags.append(f"impersonation:{brand}")
            is_suspicious = True

    if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
        flags.append("ip_address_url")
        is_suspicious = True

    vt_result = {}
    if use_vt:
        vt_data = scan_url_virustotal(url)
        if "malicious" in vt_data:
            vt_result = vt_data
            if vt_data["malicious"] > 0:
                flags.append(f"virustotal_malicious:{vt_data['malicious']}")
                is_suspicious = True

    return {"url": url, "suspicious": is_suspicious, "flags": flags, "virustotal": vt_result}


def analyze_urls_in_text(text: str) -> dict:
    urls = extract_urls(text)
    # Only use VT for top 3 URLs to avoid long wait times and rate limits
    scored = [score_url(u, use_vt=(i < 3)) for i, u in enumerate(urls)]
    suspicious_count = sum(1 for s in scored if s["suspicious"])
    return {
        "urls_found": len(urls),
        "suspicious_count": suspicious_count,
        "url_details": scored,
    }


def _invoke(messages):
    from app.tools.retry_utils import execute_with_retry
    from google.genai import types
    
    search_tool = types.Tool(google_search=types.GoogleSearch())
    
    for model in [GEMINI_MODEL] + GEMINI_MODEL_FALLBACKS:
        try:
            return execute_with_retry(
                lambda m=model: ChatGoogleGenerativeAI(
                    model=m, 
                    google_api_key=GEMINI_API_KEY, 
                    temperature=0.1
                ).invoke(messages, tools=[search_tool]).content
            )
        except Exception as e:
            if "429" not in str(e) and "RESOURCE_EXHAUSTED" not in str(e):
                raise
    raise RuntimeError("All Gemini models quota exhausted")


def gemini_analyze_text(text: str) -> dict:
    system = (
        "You are an automated phishing and scam text analyser API. "
        "Detect: urgency language, impersonation, social engineering, credential harvesting, "
        "suspicious links, fake authority claims. "
        "Use the Google Search tool to verify any claims, news, or context if needed. "
        "You MUST return your analysis strictly as a JSON object and absolutely nothing else. "
        '{"risk_score": <float 0.0-1.0>, "threat_types": [<strings>], "explanation": <string>}'
    )
    raw = _invoke([SystemMessage(content=system), HumanMessage(content=text)])
    
    if not isinstance(raw, str):
        raw = str(raw)
        
    raw = raw.strip().strip("```json").strip("```").strip()
    
    try:
        return json.loads(raw)
    except Exception as e:
        return {"risk_score": 0.0, "threat_types": [], "explanation": f"Failed to parse JSON: {raw}"}
