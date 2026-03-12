import os
import sys

# Add the project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.tools.virustotal_tools import scan_url_virustotal
from app.tools.text_tools import analyze_urls_in_text

def test_vt():
    url = "http://malware.testing.google.test/testing/malware/"
    print(f"Testing VT for URL: {url}")
    result = scan_url_virustotal(url)
    print("VT Result:", result)

def test_text_analysis():
    text = "Please check this link: http://malware.testing.google.test/testing/malware/"
    print(f"\nTesting text analysis for: {text}")
    result = analyze_urls_in_text(text)
    import json
    print("Analysis Result:", json.dumps(result, indent=2))

if __name__ == "__main__":
    test_vt()
    test_text_analysis()
