"""Malware that arrives through the dependencies, not through the network.

- A **known malicious package**: an advisory says the package (or this version) is malware. OSV
  carries these as `MAL-` records and as GHSA "Malicious Package" advisories, so the normal
  advisory match finds them; `is_malicious` only recognises them so the score and the fix differ.
- A **typosquat** (heuristic): a direct dependency one letter away from a very popular package
  that this service does not use, like `expres` for `express`. Reported, never auto-fixed.
- A **dropper in the install scripts** (heuristic): a `preinstall` or `postinstall` in package.json
  that downloads and runs code or does what ransomware does. Reported, never auto-fixed.
"""

import json
import re
from pathlib import Path

MALICIOUS_WORDS = re.compile(
    r"malicious\s+(?:package|code)|malware|backdoor|trojan|credential[- ]stealer|typosquat", re.I
)
INSTALL_SCRIPTS = ("preinstall", "install", "postinstall", "prepare", "prepublish")
DROPPER = re.compile(
    r"(?:curl|wget)\s+[^|\n]{0,200}\|\s*(?:ba|z)?sh\b"
    r"|powershell(?:\.exe)?[^\n]{0,120}\s-(?:enc|encodedcommand)\b"
    r"|(?:iex|invoke-expression)[^\n]{0,80}(?:downloadstring|webclient)"
    r"|certutil(?:\.exe)?\s+-urlcache|vssadmin(?:\.exe)?\s+delete\s+shadows"
    r"|bash\s+-i\s*>&\s*/dev/tcp/|node\s+-e\s+[\"'][^\"']*(?:child_process|eval\()",
    re.I,
)
POPULAR = {
    "npm": {
        "express",
        "lodash",
        "react",
        "react-dom",
        "axios",
        "moment",
        "chalk",
        "request",
        "commander",
        "debug",
        "async",
        "underscore",
        "bluebird",
        "uuid",
        "webpack",
        "typescript",
        "eslint",
        "prettier",
        "jest",
        "mocha",
        "vue",
        "angular",
        "jquery",
        "dotenv",
        "cors",
        "body-parser",
        "mongoose",
        "mysql",
        "redis",
        "socket.io",
        "passport",
        "jsonwebtoken",
        "bcrypt",
        "bcryptjs",
        "colors",
        "yargs",
        "minimist",
        "glob",
        "rimraf",
        "mkdirp",
        "semver",
        "cheerio",
        "puppeteer",
        "next",
        "nodemon",
        "morgan",
        "helmet",
        "validator",
        "ws",
        "pg",
        "sequelize",
        "knex",
        "handlebars",
        "ejs",
        "pug",
        "inquirer",
        "ora",
        "cross-env",
        "node-fetch",
        "tslib",
        "rxjs",
        "classnames",
        "immer",
        "redux",
        "date-fns",
        "dayjs",
        "ramda",
        "zod",
        "joi",
        "yup",
        "multer",
        "formidable",
        "nock",
    },
    "PyPI": {
        "requests",
        "numpy",
        "pandas",
        "flask",
        "django",
        "urllib3",
        "boto3",
        "pytest",
        "setuptools",
        "pip",
        "wheel",
        "six",
        "pyyaml",
        "jinja2",
        "click",
        "cryptography",
        "pillow",
        "scipy",
        "matplotlib",
        "sqlalchemy",
        "certifi",
        "idna",
        "attrs",
        "packaging",
        "pydantic",
        "fastapi",
        "uvicorn",
        "httpx",
        "aiohttp",
        "beautifulsoup4",
        "lxml",
        "psycopg2",
        "pymysql",
        "redis",
        "celery",
        "gunicorn",
        "tornado",
        "scikit-learn",
        "tensorflow",
        "torch",
        "keras",
        "openpyxl",
        "colorama",
        "tqdm",
        "rich",
        "typer",
        "python-dateutil",
        "pytz",
        "markupsafe",
        "werkzeug",
        "paramiko",
        "pyjwt",
        "bcrypt",
        "python-dotenv",
        "toml",
        "tomli",
        "regex",
        "docker",
        "kubernetes",
        "selenium",
    },
}


def is_malicious(records: list[dict], summary: str) -> bool:
    """Does any advisory in this group say the package is malware?"""
    for record in records:
        if record["id"].startswith("MAL-"):
            return True
        if "malicious-packages-origins" in (record.get("database_specific") or {}):
            return True
    return bool(MALICIOUS_WORDS.search(summary))


def _distance_one(a: str, b: str) -> bool:
    """Are the two names exactly one insertion, deletion or substitution apart?"""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b, strict=True)) == 1
    short, long = sorted((a, b), key=len)
    return any(long[:i] + long[i + 1 :] == short for i in range(len(long)))


def direct_names(folder: Path) -> tuple[str, list[str]]:
    """(ecosystem, direct dependency names) for the manifests Hedwig can read here."""
    package_json = folder / "package.json"
    if package_json.is_file():
        try:
            data = json.loads(package_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return "npm", []
        return "npm", [*data.get("dependencies", {}), *data.get("devDependencies", {})]
    requirements = folder / "requirements.txt"
    if requirements.is_file():
        names = []
        for line in requirements.read_text(encoding="utf-8").splitlines():
            match = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)", line.split("#", 1)[0])
            if match:
                names.append(re.sub(r"[-_.]+", "-", match.group(1)).lower())
        return "PyPI", names
    return "", []


def typosquats(folder: Path) -> list[tuple[str, str]]:
    """(dependency, the popular package it imitates)."""
    ecosystem, names = direct_names(folder)
    popular = POPULAR.get(ecosystem, set())
    used = {n.lower() for n in names}
    found = []
    for name in names:
        lowered = name.lower()
        if len(lowered) < 5 or lowered in popular:
            continue
        for real in sorted(popular):
            if real not in used and _distance_one(lowered, real):
                found.append((name, real))
                break
    return found


def install_script_droppers(folder: Path) -> list[tuple[str, str]]:
    """(script name, the command) for install-time scripts that look like a dropper."""
    path = folder / "package.json"
    if not path.is_file():
        return []
    try:
        scripts = json.loads(path.read_text(encoding="utf-8")).get("scripts", {})
    except (OSError, json.JSONDecodeError):
        return []
    return [
        (name, command)
        for name, command in scripts.items()
        if name in INSTALL_SCRIPTS and isinstance(command, str) and DROPPER.search(command)
    ]
