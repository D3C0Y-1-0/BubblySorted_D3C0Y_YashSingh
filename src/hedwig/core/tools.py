"""Tools Hedwig fetches for itself. Today that is tectonic, the LaTeX-to-PDF compiler."""

import hashlib
import io
import os
import platform
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path

import httpx

from hedwig import settings

BIN_DIR = settings.CONFIG_DIR / "bin"
TECTONIC_VERSION = "0.15.0"
TECTONIC_URL = (
    "https://github.com/tectonic-typesetting/tectonic/releases/download/"
    "tectonic%40{version}/tectonic-{version}-{target}.{ext}"
)
# target -> (archive extension, SHA-256 of the official release asset)
TECTONIC_ASSETS = {
    "x86_64-unknown-linux-musl": (
        "tar.gz",
        "dfb82876f2986862996e564fa507a9e576e0c1e3bee63c2c1bd677c2543e6407",
    ),
    "aarch64-unknown-linux-musl": (
        "tar.gz",
        "1f59f9fb8eb65e8ba18658fc9016767e7d3e12488ded8b8fffa34254e51ce42c",
    ),
    "x86_64-pc-windows-msvc": (
        "zip",
        "1d6bb76f049c8a3774f6e9d66e4b04e1a8c3dcb37527b6b41b7e894328e7bf29",
    ),
    "x86_64-apple-darwin": (
        "tar.gz",
        "dd42576eaa4c0df58c243dd78b7b864d9deb405ffdfcdadd1b79a31faceab747",
    ),
    "aarch64-apple-darwin": (
        "tar.gz",
        "24bd46566fa30d41101848405e9cbc4645edb92d8f857c9d21262174fb70cd33",
    ),
}
DOWNLOAD_TIMEOUT = 300


class ToolError(Exception):
    pass


def _binary_name() -> str:
    return "tectonic.exe" if os.name == "nt" else "tectonic"


def find_tectonic() -> Path | None:
    on_path = shutil.which("tectonic")
    if on_path:
        return Path(on_path)
    ours = BIN_DIR / _binary_name()
    return ours if ours.is_file() else None


def _target() -> str | None:
    machine = platform.machine().lower()
    arm = machine in ("arm64", "aarch64")
    system = platform.system()
    if system == "Linux":
        return "aarch64-unknown-linux-musl" if arm else "x86_64-unknown-linux-musl"
    if system == "Darwin":
        return "aarch64-apple-darwin" if arm else "x86_64-apple-darwin"
    if system == "Windows" and not arm:
        return "x86_64-pc-windows-msvc"
    return None


def _extract(data: bytes, ext: str) -> bytes:
    """The tectonic binary from the archive. Nothing else is ever written to disk."""
    name = _binary_name()
    if ext == "zip":
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            return archive.read(name)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        member = archive.extractfile(name)
        if member is None:
            raise ToolError(f"{name} is not in the downloaded archive")
        return member.read()


def ensure_tectonic(say=print) -> Path:
    """tectonic from PATH or ~/.hedwig/bin, downloading the pinned official release if absent."""
    found = find_tectonic()
    if found:
        return found
    target = _target()
    if target not in TECTONIC_ASSETS:
        raise ToolError(
            f"no prebuilt tectonic for {platform.system()} {platform.machine()}; "
            "install it from https://tectonic-typesetting.github.io and run again"
        )
    ext, expected = TECTONIC_ASSETS[target]
    url = TECTONIC_URL.format(version=TECTONIC_VERSION, target=target, ext=ext)
    say(f"Downloading tectonic {TECTONIC_VERSION} (PDF engine, one time) …")
    try:
        response = httpx.get(url, follow_redirects=True, timeout=DOWNLOAD_TIMEOUT)
        response.raise_for_status()
    except httpx.HTTPError as err:
        raise ToolError(f"could not download tectonic: {err}") from err
    if hashlib.sha256(response.content).hexdigest() != expected:
        raise ToolError("the downloaded tectonic does not match its pinned checksum; not installed")
    try:
        binary = _extract(response.content, ext)
    except (OSError, KeyError, tarfile.TarError, zipfile.BadZipFile) as err:
        raise ToolError(f"could not unpack tectonic: {err}") from err
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    path = BIN_DIR / _binary_name()
    path.write_bytes(binary)
    path.chmod(0o755)
    check = subprocess.run([str(path), "--version"], capture_output=True, text=True)
    if check.returncode != 0:
        path.unlink(missing_ok=True)
        raise ToolError(f"the downloaded tectonic does not run: {check.stderr.strip()[-200:]}")
    return path
