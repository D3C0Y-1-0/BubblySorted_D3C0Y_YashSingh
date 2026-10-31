"""The link to Hedwig, through files only.

When ring 6 stops an attack payload, the request line is appended to that service's access log
(`<bank>/<service>/logs/access.log`, or the `log_path` that `.hedwig.yml` sets) in the format
Hedwig's evidence reader already parses. `hedwig scan` and `hedwig status` then show evidence
level 3 for the service, with no change to Hedwig. The Guard never edits `.hedwig.yml`.
"""

import sys
from datetime import UTC, datetime
from pathlib import Path

import yaml


class HedwigLink:
    def __init__(self, bank_root: Path | None) -> None:
        self.bank_root = bank_root
        self._paths: dict[str, Path] = {}
        self._overrides = self._read_overrides()

    def _read_overrides(self) -> dict[str, str]:
        if not self.bank_root:
            return {}
        try:
            data = yaml.safe_load((self.bank_root / ".hedwig.yml").read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            return {}
        services = (data or {}).get("services") or {}
        return {
            name: spec["log_path"]
            for name, spec in services.items()
            if isinstance(spec, dict) and spec.get("log_path")
        }

    def log_path(self, service: str) -> Path | None:
        if not self.bank_root or not (self.bank_root / service).is_dir():
            return None
        if service not in self._paths:
            override = self._overrides.get(service)
            self._paths[service] = (
                self.bank_root / override
                if override
                else self.bank_root / service / "logs" / "access.log"
            )
        return self._paths[service]

    def record(self, service: str | None, ip: str, method: str, target: str, status: int,
               rule: str) -> bool:  # fmt: skip
        """Append one attack line. Returns False when the service has no log to write to."""
        path = self.log_path(service) if service else None
        if path is None:
            return False
        stamp = datetime.now(UTC).isoformat(timespec="seconds")
        target = target.replace("\n", " ").replace("\r", " ")[:2000]
        line = f'{stamp} {ip} - "{method} {target} HTTP/1.1" {status} [chakravyuha ring6 {rule}]\n'
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(line)
            return True
        except OSError as error:
            print(f"chakravyuha: cannot write {path}: {error}", file=sys.stderr)
            return False
