import os
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"))

GEMINI_API_KEY: str = os.environ["GEMINI_API_KEY"]
HUGGING_FACE_TOKEN: str = os.environ["HUGGING_FACE_TOKEN"]
VIRUS_TOTAL_API_KEY: str = os.environ.get("VIRUS_TOTAL", "")

HF_IMAGE_MODEL = "dima806/deepfake_vs_real_image_detection"
HF_AUDIO_MODEL = "mo-thecreator/Deepfake-audio-detection"
GEMINI_MODEL = "gemini-2.5-flash"
GEMINI_MODEL_FALLBACKS = ["gemini-2.5-flash","gemini-2.5-flash-lite","gemini-flash-latest","gemma-3-27b-it"]

