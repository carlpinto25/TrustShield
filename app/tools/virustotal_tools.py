import requests
import base64
import hashlib
import time
from app.config import VIRUS_TOTAL_API_KEY

def get_url_id(url: str) -> str:
    """VT v3 uses base64 without padding for URL IDs."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def scan_url_virustotal(url: str) -> dict:
    if not VIRUS_TOTAL_API_KEY:
        return {"error": "VirusTotal API key not configured"}

    url_id = get_url_id(url)
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        "x-apikey": VIRUS_TOTAL_API_KEY
    }

    try:
        response = requests.get(endpoint, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "link": f"https://www.virustotal.com/gui/url/{url_id}"
            }
        elif response.status_code == 404:
            return {"status": "not_found", "message": "URL not previously scanned by VirusTotal"}
        else:
            return {"error": f"VirusTotal API returned {response.status_code}", "details": response.text}
    except Exception as e:
        return {"error": str(e)}

def scan_file_virustotal(file_content: bytes, filename: str) -> dict:
    """
    Scans a file using VirusTotal v3 API. 
    First checks by hash, then uploads if not found.
    """
    if not VIRUS_TOTAL_API_KEY:
        return {"error": "VirusTotal API key not configured"}

    sha256_hash = hashlib.sha256(file_content).hexdigest()
    headers = {"x-apikey": VIRUS_TOTAL_API_KEY}
    
    # 1. Check if hash already exists
    endpoint = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    try:
        response = requests.get(endpoint, headers=headers)
        if response.status_code == 200:
            return _parse_vt_file_response(response.json())
        
        # 2. If not found, upload the file
        if response.status_code == 404:
            upload_url = "https://www.virustotal.com/api/v3/files"
            # For files > 32MB, we'd need a special upload URL, but let's assume standard for now
            files = {"file": (filename, file_content)}
            upload_response = requests.post(upload_url, headers=headers, files=files)
            
            if upload_response.status_code == 200:
                analysis_id = upload_response.json().get("data", {}).get("id")
                # In a real app, we might poll or return the ID. 
                # For this tool, let's wait a few seconds and try to get the report by hash
                # usually hash report is available shortly after upload if it's small
                time.sleep(2) 
                # Re-check by hash
                response = requests.get(endpoint, headers=headers)
                if response.status_code == 200:
                    return _parse_vt_file_response(response.json())
                return {"status": "queued", "analysis_id": analysis_id, "message": "File uploaded, analysis in progress."}
            else:
                return {"error": f"Upload failed: {upload_response.status_code}", "details": upload_response.text}
                
        return {"error": f"VT API error: {response.status_code}", "details": response.text}
    except Exception as e:
        return {"error": str(e)}

def _parse_vt_file_response(data: dict) -> dict:
    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "file_type": attributes.get("type_description", "unknown"),
        "size": attributes.get("size", 0),
        "sha256": attributes.get("sha256", ""),
        "link": f"https://www.virustotal.com/gui/file/{attributes.get('sha256')}"
    }
