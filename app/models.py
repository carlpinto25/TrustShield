from pydantic import BaseModel, Field
from typing import Any


class TextRequest(BaseModel):
    text: str


class AnalysisResult(BaseModel):
    risk_score: float = Field(..., ge=0.0, le=1.0, description="0.0 = safe, 1.0 = critical threat")
    risk_level: str = Field(..., description="LOW | MEDIUM | HIGH | CRITICAL")
    threat_types: list[str] = Field(default_factory=list)
    explanation: str
    tool_outputs: dict[str, Any] = Field(default_factory=dict)
