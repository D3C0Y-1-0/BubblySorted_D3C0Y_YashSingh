"""User settings stored in ~/.hedwig/config.toml, overridable by environment variables."""

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

import tomli_w

CONFIG_DIR = Path.home() / ".hedwig"
CONFIG_PATH = CONFIG_DIR / "config.toml"


@dataclass(frozen=True)
class Key:
    env: str
    secret: bool
    default: str
    description: str


KEYS: dict[str, Key] = {
    "groq_api_key": Key("GROQ_API_KEY", True, "", "Groq API key (all LLM agents)"),
    "model": Key("HEDWIG_MODEL", False, "qwen/qwen3.8-27b", "Groq model used by every agent"),
    "smtp_user": Key("SMTP_USER", False, "", "SMTP username for PM reports"),
    "smtp_pass": Key("SMTP_PASS", True, "", "SMTP password / app password"),
    "pm_email": Key(
        "PM_EMAIL",
        False,
        "yash1812ys@gmail.com, anirudh.vineet8@gmail.com, "
        "titanparth.2801@gmail.com, prathamtsec@gmail.com",
        "Project manager emails (comma separated)",
    ),
}


def _read_file() -> dict[str, str]:
    if not CONFIG_PATH.exists():
        return {}
    with CONFIG_PATH.open("rb") as f:
        data = tomllib.load(f)
    return {k: str(v) for k, v in data.items() if k in KEYS}


def load() -> dict[str, str]:
    """Defaults, then config file, then environment variables."""
    return {name: value for name, (value, _) in load_with_source().items()}


def load_with_source() -> dict[str, tuple[str, str]]:
    """Each key's value and where it came from: env, file or default."""
    file_values = _read_file()
    result: dict[str, tuple[str, str]] = {}
    for name, key in KEYS.items():
        if os.environ.get(key.env):
            result[name] = (os.environ[key.env], "env")
        elif file_values.get(name):
            result[name] = (file_values[name], "file")
        else:
            result[name] = (key.default, "default")
    return result


def get(name: str) -> str:
    return load()[name]


def save(name: str, value: str) -> None:
    if name not in KEYS:
        raise KeyError(name)
    data = _read_file()
    data[name] = value
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with CONFIG_PATH.open("wb") as f:
        tomli_w.dump(data, f)
    if os.name != "nt":
        CONFIG_PATH.chmod(0o600)


def mask(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "****"
    return "*" * (len(value) - 4) + value[-4:]
