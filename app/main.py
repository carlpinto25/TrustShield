"""
FastAPI entrypoint for the Anti-Phishing Backend.
Serves all 4 analysis routers and the plain HTML demo frontend.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

from app.routers import text, image, video, audio, file

app = FastAPI(
    title="Anti-Phishing AI Backend",
    description="LangChain + Gemini powered phishing and deepfake detection API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(text.router, prefix="/analyze", tags=["Text"])
app.include_router(image.router, prefix="/analyze", tags=["Image"])
app.include_router(video.router, prefix="/analyze", tags=["Video"])
app.include_router(audio.router, prefix="/analyze", tags=["Audio"])
app.include_router(file.router, prefix="/analyze", tags=["File"])

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")


@app.get("/", include_in_schema=False)
async def serve_frontend():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))


@app.get("/health")
async def health():
    return {"status": "ok"}
