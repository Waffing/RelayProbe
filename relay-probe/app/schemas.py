from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, StrictBool, model_validator

from .config import Controls


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class Target(Model):
    base_url: str = Field(min_length=1, max_length=2048)
    api_key: SecretStr = Field(min_length=1, max_length=4096, exclude=True)
    proxy: SecretStr | None = Field(None, exclude=True)
    local_network_compat: StrictBool = Field(False, exclude=True)


class Prices(Model):
    input: float = Field(ge=0)
    cached: float = Field(ge=0)
    output: float = Field(ge=0)


class Ledger(Model):
    kind: Literal["balance", "used"] = "balance"
    before: float | None = Field(None, ge=0)
    after: float | None = Field(None, ge=0)
    units_per_usd: float = Field(1, gt=0)


class RunRequest(Target):
    name: str = Field("未命名渠道", max_length=100)
    model: str = Field(min_length=1, max_length=200)
    protocol: Literal["auto", "responses", "chat"] = "auto"
    profile_id: str = "builtin"
    bare: bool = False
    mode: Literal["quick", "full", "stress"] = "quick"
    probe_ids: list[int] | None = Field(None, min_length=1, max_length=40)
    expensive: list[Literal[35, 36, 40]] = Field(default_factory=list)
    allow_50: bool = False
    advertised_cache: float | None = Field(None, ge=0, le=100)
    panel_units_per_usd: float | None = Field(None, gt=0)
    prices: Prices | None = None
    ledger: Ledger = Field(default_factory=Ledger)
    controls: Controls = Field(default_factory=Controls)
    fingerprints: list[int] = Field(default_factory=lambda: [4233, 4157], max_length=256)

    @model_validator(mode="after")
    def check_options(self):
        if self.probe_ids and any(i < 1 or i > 40 for i in self.probe_ids):
            raise ValueError("探针编号须为 1–40")
        if any(w < 0 for w in self.controls.weights) or not sum(self.controls.weights):
            raise ValueError("权重须非负且至少一项大于零")
        r = self.controls.rules
        if not r.score_c <= r.score_b <= r.score_a:
            raise ValueError("裁决分界须为 C ≤ B ≤ A")
        return self


class Profile(Model):
    id: str = ""
    name: str = Field(min_length=1, max_length=160)
    client: str = "Codex"
    source: Literal["自建基准模板", "实机抓包复刻", "原文导入"] = "自建基准模板"
    protocol: Literal["responses", "chat"] = "responses"
    headers: dict[str, str] = Field(default_factory=dict)
    body: dict = Field(default_factory=dict)
    baseline_tokens: int = 0


class Exchange(Model):
    seq: int
    probe: int
    label: str
    protocol: str
    disguised: bool
    method: str = "POST"
    path: str
    headers: dict = Field(default_factory=dict)
    body: dict = Field(default_factory=dict)
    response_headers: dict = Field(default_factory=dict)
    status: int | None = None
    error: str | None = None
    snippet: str = ""
    elapsed: float = 0
    phases: dict = Field(default_factory=dict)
    ttft: float | None = None
    chunks: list[dict] = Field(default_factory=list)
    events: list[str] = Field(default_factory=list)
    stream: bool = False
    complete: bool = False
    finish: str | None = None
    text: str = ""
    response_id: str | None = None
    model: str | None = None
    fingerprint: str | None = None
    usage: dict | None = None
    counts: dict = Field(default_factory=dict)
    local_input: int = 0
    local_output: int = 0
    input_delta: int | None = None
    calls: list[dict] = Field(default_factory=list)
    output_items: list[dict] = Field(default_factory=list)
    cost: float | None = None


class Finding(Model):
    id: int
    name: str
    status: Literal["通过", "需关注", "异常", "证据不足", "待对照确切指纹"]
    strength: Literal["实测检出", "疑似", "未检出"]
    summary: str
    samples: int
    evidence: list[int]
    metrics: dict[str, Any] = Field(default_factory=dict)
    score: float | None = None
    hard: bool = False


class Report(Model):
    version: int = 1
    run_id: str
    meta: dict
    findings: list[Finding]
    requests: list[Exchange]
    head: dict
    verdict: dict
    totals: dict
    pending: list[str]
