"""Advisory data: OSV records, CISA KEV and EPSS.

Live mode asks the public APIs and caches what it gets. Offline mode reads a folder with the
same layout as the cache and as fixtures/advisories:

    osv/vulns/<ID>.json   one OSV record per file
    kev.json              CISA KEV catalog
    epss.json             EPSS API response ({"data": [...]})
"""

import json
import re
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

from hedwig import settings
from hedwig.core import versions
from hedwig.core.models import Package

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

DAY = 24 * 3600
VULN_TTL = 7 * DAY
DEFAULT_CACHE = settings.CONFIG_DIR / "cache"
# advisories bundled for `hedwig replay`: same layout as the cache
REPLAY_DIR = Path(__file__).resolve().parent.parent / "data" / "replay"


def replay_names() -> list[str]:
    return sorted(path.stem for path in (REPLAY_DIR / "osv" / "vulns").glob("*.json"))


class AdvisoryUnavailable(Exception):
    """No advisory data could be found, live or cached."""


def norm_name(ecosystem: str, name: str) -> str:
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem == "Packagist":
        return name.lower()
    return name


def affected_entries(record: dict, package: Package) -> list[dict]:
    """The affected[] entries of an OSV record that describe this package."""
    wanted = norm_name(package.ecosystem, package.name)
    return [
        entry
        for entry in record.get("affected", [])
        if entry.get("package", {}).get("ecosystem") == package.ecosystem
        and norm_name(package.ecosystem, entry["package"].get("name", "")) == wanted
    ]


def is_affected(record: dict, package: Package) -> bool:
    for entry in affected_entries(record, package):
        if package.version in entry.get("versions", []):
            return True
        for item in entry.get("ranges", []):
            if item.get("type") in ("SEMVER", "ECOSYSTEM") and versions.in_range(
                package.version, item.get("events", [])
            ):
                return True
    return False


class AdvisorySource:
    def __init__(
        self,
        offline: bool = False,
        directory: Path | None = None,
        only: set[str] | None = None,
    ) -> None:
        self.offline = offline
        self.directory = Path(directory) if directory else DEFAULT_CACHE
        self.only = only  # when set, only these records (by file name) are used
        self.warnings: list[str] = []
        self._records: dict[str, dict] | None = None

    # -- local records ------------------------------------------------------------------

    def _vuln_dir(self) -> Path:
        return self.directory / "osv" / "vulns"

    def _local_records(self) -> dict[str, dict]:
        if self._records is None:
            folder = self._vuln_dir()
            if not folder.is_dir():
                raise AdvisoryUnavailable(f"no advisory data in {folder}")
            self._records = {
                path.stem: json.loads(path.read_text(encoding="utf-8"))
                for path in sorted(folder.glob("*.json"))
                if self.only is None or path.stem in self.only
            }
        return self._records

    def _match_local(self, packages: list[Package]) -> dict[tuple, list[dict]]:
        records = list(self._local_records().values())
        return {_key(p): [r for r in records if is_affected(r, p)] for p in packages}

    # -- matching -----------------------------------------------------------------------

    def match(self, packages: list[Package]) -> dict[tuple, list[dict]]:
        """OSV records for each (ecosystem, name, version)."""
        unique = list({_key(p): p for p in packages}.values())
        if self.offline:
            return self._match_local(unique)
        try:
            return self._match_live(unique)
        except (httpx.HTTPError, OSError) as err:
            self.warnings.append(f"OSV unreachable ({type(err).__name__}); using cached records")
            return self._match_local(unique)

    def _match_live(self, packages: list[Package]) -> dict[tuple, list[dict]]:
        ids_by_package: dict[tuple, list[str]] = {}
        with httpx.Client(timeout=30) as client:
            for start in range(0, len(packages), 1000):
                chunk = packages[start : start + 1000]
                queries = [
                    {
                        "package": {"ecosystem": p.ecosystem, "name": p.name},
                        "version": p.version,
                    }
                    for p in chunk
                ]
                response = client.post(OSV_BATCH, json={"queries": queries})
                response.raise_for_status()
                for package, result in zip(chunk, response.json()["results"], strict=True):
                    ids_by_package[_key(package)] = [v["id"] for v in result.get("vulns", [])]
            wanted = sorted({i for ids in ids_by_package.values() for i in ids})
            with ThreadPoolExecutor(max_workers=16) as pool:
                fetched = list(pool.map(lambda i: self._vuln(client, i), wanted))
        records = {i: r for i, r in zip(wanted, fetched, strict=True) if r}
        return {k: [records[i] for i in ids if i in records] for k, ids in ids_by_package.items()}

    def _vuln(self, client: httpx.Client, vuln_id: str) -> dict | None:
        path = self._vuln_dir() / f"{vuln_id}.json"
        if _fresh(path, VULN_TTL):
            return json.loads(path.read_text(encoding="utf-8"))
        try:
            response = client.get(OSV_VULN.format(id=vuln_id))
            response.raise_for_status()
        except httpx.HTTPError:
            self.warnings.append(f"could not fetch {vuln_id}")
            return None
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(response.text, encoding="utf-8")
        return response.json()

    # -- KEV and EPSS -------------------------------------------------------------------

    def kev_cves(self) -> set[str] | None:
        """CVE ids in the CISA KEV catalog, or None when the catalog couldn't be loaded."""
        path = self.directory / "kev.json"
        data = self._cached(path, DAY, lambda: _get_json(KEV_URL, timeout=60), "KEV")
        if data is None:
            return None
        return {v["cveID"] for v in data.get("vulnerabilities", [])}

    def epss(self, cves: list[str]) -> dict[str, float]:
        path = self.directory / "epss.json"
        scores = _read_epss(path) if (self.offline or _fresh(path, DAY)) else {}
        missing = sorted(set(cves) - set(scores))
        if missing and not self.offline:
            try:
                for start in range(0, len(missing), 100):
                    chunk = missing[start : start + 100]
                    data = _get_json(EPSS_URL, params={"cve": ",".join(chunk)}, timeout=30)
                    scores.update({row["cve"]: float(row["epss"]) for row in data["data"]})
                path.parent.mkdir(parents=True, exist_ok=True)
                rows = [{"cve": c, "epss": str(s)} for c, s in scores.items()]
                path.write_text(json.dumps({"data": rows}), encoding="utf-8")
            except (httpx.HTTPError, OSError, KeyError, ValueError) as err:
                self.warnings.append(f"EPSS unavailable ({type(err).__name__})")
        return {c: scores[c] for c in cves if c in scores}

    def _cached(self, path: Path, ttl: int, fetch: Callable[[], dict], label: str) -> dict | None:
        if self.offline and not path.is_file():
            self.warnings.append(f"{label} data is not cached; run one scan online to fetch it")
            return None
        if self.offline or _fresh(path, ttl):
            return json.loads(path.read_text(encoding="utf-8"))
        try:
            data = fetch()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data), encoding="utf-8")
            return data
        except (httpx.HTTPError, OSError, ValueError) as err:
            self.warnings.append(f"{label} unavailable ({type(err).__name__})")
            if path.is_file():
                return json.loads(path.read_text(encoding="utf-8"))
            return None


def _key(package: Package) -> tuple[str, str, str]:
    return (package.ecosystem, norm_name(package.ecosystem, package.name), package.version)


def _fresh(path: Path, ttl: int) -> bool:
    return path.is_file() and time.time() - path.stat().st_mtime < ttl


def _get_json(url: str, params: dict | None = None, timeout: float = 30) -> dict:
    response = httpx.get(url, params=params, timeout=timeout, follow_redirects=True)
    response.raise_for_status()
    return response.json()


def _read_epss(path: Path) -> dict[str, float]:
    if not path.is_file():
        return {}
    rows = json.loads(path.read_text(encoding="utf-8")).get("data", [])
    return {row["cve"]: float(row["epss"]) for row in rows}
