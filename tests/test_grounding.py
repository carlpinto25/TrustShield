import os
import sys

# Add the project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.tools.text_tools import gemini_analyze_text

def test_grounding():
    # A prompt that requires recent news to answer correctly
    text = "Is the company 'DeepSeek' currently in the news for anything related to AI or data privacy? Could this be a scam related to them?"
    print(f"Testing text analysis with grounding prompt: {text}")
    print("This should leverage Google Search to find recent news.")
    
    result = gemini_analyze_text(text)
    
    print("\n--- Grounded Analysis Result ---")
    import json
    print(json.dumps(result, indent=2))
    
    if "explanation" in result and "DeepSeek" in result["explanation"]:
        print("\n✅ Verification SUCCESS: The model responded with context about DeepSeek.")
    else:
        print("\n❌ Verification FAILED: The model did not provide recognizable context.")

if __name__ == "__main__":
    test_grounding()
