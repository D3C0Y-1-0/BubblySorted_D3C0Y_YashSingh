"""Settings from `guard/chakravyuha.yml`. Everything has a safe default."""

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

GUARD_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = GUARD_ROOT / "chakravyuha.yml"

Mode = Literal["block", "monitor"]


class Suspicion(BaseModel):
    tarpit: float = 3
    hard_challenge: float = 5
    trap: float = 10
    half_life_s: float = 600  # the score halves every 10 minutes


class Challenge(BaseModel):
    difficulty: int = 18  # proof-of-work bits; about 200 ms in a browser
    hard_bits: int = 4  # extra bits once a client reaches suspicion.hard_challenge
    session_minutes: float = 30  # a third of this for clients at hard_challenge
    token_seconds: int = 120  # how long an issued puzzle can be solved


class Flood(BaseModel):
    burst_factor: float = 2.0  # bucket size = rate x burst_factor
    max_in_flight: int = 500  # global cap on requests being handled
    ban_after: int = 20  # rate-limited requests within ban_window_s that earn a ban
    ban_window_s: float = 10
    ban_minutes: float = 5
    max_header_bytes: int = 16_384
    body_timeout_s: float = 10  # slow-request limit for reading the body
    tarpit_min_s: float = 0.5
    tarpit_max_s: float = 3.0
    tarpit_cap: int = 200  # tarpitted connections held at once; beyond it, 429


class Login(BaseModel):
    max_failures: int = 8  # failures from one IP within window_s that trip ring 5
    window_s: float = 60
    backoff_step_s: float = 0.25  # each failure adds this much delay before the answer
    backoff_max_s: float = 3.0


class Agents(BaseModel):
    enabled: bool = True
    interval_s: float = 5  # the agents' loop
    window_s: float = 60  # how far back the Scout looks
    distributed_failures: int = 30  # rule A: failures on one username ...
    distributed_ips: int = 10  # ... from this many IPs
    spray_usernames: int = 15  # rule B: one password against this many usernames ...
    spray_ips: int = 3  # ... from this many IPs
    campaign_trap_minutes: float = 30
    throttle_minutes: float = 10
    throttle_interval_s: float = 5  # a throttled username gets one login attempt per interval
    active_s: float = 120  # a campaign is active until it has been quiet this long
    alert_traps: int = 3
    siege_traps: int = 20
    alarm_siege_s: float = 600  # a honeytoken alarm keeps the level at siege this long
    step_down_s: float = 120  # quiet time before the level steps down one notch
    rotate_minutes: float = 10  # honeytoken rotation
    ai_every_s: float = 15  # at most one model call per interval unless a campaign is new


class Elk(BaseModel):
    """ELK connection settings. CHAKRA_LOGSTASH, CHAKRA_ELASTIC_URL and CHAKRA_KIBANA_URL win."""

    enabled: bool = True
    logstash: str = "127.0.0.1:5000"
    elastic_url: str = "http://127.0.0.1:9200"
    kibana_url: str = "http://127.0.0.1:5601"
    index: str = "chakravyuha-*"


class Service(BaseModel):
    upstream: str
    prefix: str | None = None  # default "/<name>"; "/" catches everything else
    rate: float = 20  # requests per second per IP
    login_paths: list[str] = Field(default_factory=list)
    routes: list[str] = Field(default_factory=list)  # "METHOD /path"; used by ring 4
    challenge: bool = True
    api_key_env: str | None = None  # for challenge: false
    redirect_hosts: list[str] = Field(default_factory=list)
    uploads: bool | list[str] = False
    mode: Mode | None = None  # overrides the global mode
    health_path: str = "/health"


class Config(BaseModel):
    mode: Mode = "block"
    allowlist: list[str] = Field(default_factory=list)
    trap_minutes: float = 30
    max_body_bytes: int = 10 * 1024 * 1024
    suspicion: Suspicion = Suspicion()
    challenge: Challenge = Challenge()
    flood: Flood = Flood()
    login: Login = Login()
    elk: Elk = Elk()
    agents: Agents = Agents()
    services: dict[str, Service] = Field(default_factory=dict)
    data_dir: Path | None = GUARD_ROOT / "data"
    bank_root: Path | None = GUARD_ROOT / "bank"  # where ring 6 appends to service access logs
    stdout_events: bool = True
    digest_delay_s: float = 30  # first unreported event starts this timer, then one PM email
    digest_cooldown_s: float = 300  # ... and this cool-down, so a burst sends one email

    @field_validator("trap_minutes")
    @classmethod
    def _cap_trap(cls, value: float) -> float:
        return min(max(value, 1), 60)

    @model_validator(mode="after")
    def _prefixes(self) -> "Config":
        for name, service in self.services.items():
            prefix = service.prefix if service.prefix is not None else f"/{name}"
            service.prefix = "/" + prefix.strip("/") if prefix.strip("/") else "/"
        return self

    def service_mode(self, service: Service | None) -> Mode:
        return service.mode if service and service.mode else self.mode


def load(path: Path | None = None) -> Config:
    path = path or DEFAULT_CONFIG
    if not path.is_file():
        return Config()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    config = Config.model_validate(data)
    for field in ("data_dir", "bank_root"):
        value = getattr(config, field)
        if value and not value.is_absolute():
            setattr(config, field, path.parent / value)
    return config
