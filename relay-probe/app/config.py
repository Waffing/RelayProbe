import os
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


ROOT = Path(__file__).resolve().parents[1]
DATA = Path(os.environ.get("PROBE_DATA_DIR", ROOT / ".runtime"))
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8787"))
ACCESS_PASSWORD = os.environ.get("ACCESS_PASSWORD", "")
ALLOW_PRIVATE = os.environ.get("ALLOW_PRIVATE_TARGETS", "false").lower() == "true"
HISTORY_TTL = 1800


class Rules(BaseModel):
    """可编辑的候选阈值。它们不是厂商承诺或独立核实的基准。"""
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    input_tolerance: int = Field(2, ge=0)
    output_tolerance: int = Field(3, ge=0)
    high_injection: int = Field(1000, ge=1)
    high_cache: float = Field(.70, gt=0, le=1)
    warm_ttft_ratio: float = Field(.80, gt=0, le=1)
    answer_ttft_ratio: float = Field(.40, gt=0, le=1)
    effort_ratio: float = Field(1.15, ge=1)
    duration_ratio: float = Field(1.10, ge=1)
    tail_ratio: float = Field(.65, gt=0, le=1)
    burst_gap_s: float = Field(2, gt=0)
    timeout_window_s: float = Field(3, ge=0)
    assumed_cache_ratio: float = Field(.25, ge=0, le=1)
    score_a: float = Field(90, ge=0, le=100)
    score_b: float = Field(75, ge=0, le=100)
    score_c: float = Field(50, ge=0, le=100)


class Controls(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    connect_s: float = Field(15, gt=0, le=300)
    read_s: float = Field(60, gt=0, le=900)
    heavy_s: float = Field(150, gt=0, le=1800)
    max_requests: int = Field(180, ge=1, le=2000)
    max_tokens: int = Field(600_000, ge=1, le=10_000_000)
    consecutive_failures: int = Field(3, ge=1, le=20)
    cache_repeats: int = Field(8, ge=2, le=40)
    sustained_rpm: int = Field(30, ge=1, le=120)
    budget_usd: float | None = Field(None, gt=0)
    weights: list[float] = Field(default_factory=lambda: [1] * 5, min_length=5, max_length=5)
    rules: Rules = Field(default_factory=Rules)
