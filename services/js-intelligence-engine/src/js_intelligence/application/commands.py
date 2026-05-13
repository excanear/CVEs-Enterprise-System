from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class AnalyzeJSCommand(BaseModel):
    """Command to trigger a JS intelligence analysis job."""

    model_config = ConfigDict(frozen=True)

    tenant_id: str
    target_url: str
    correlation_id: str = ""
    max_js_files: int = Field(default=50, ge=1, le=200)
    fetch_source_maps: bool = True
    timeout_seconds: int = Field(default=300, ge=30, le=1800)
    max_file_size_bytes: int = Field(default=10_485_760, ge=1024)
