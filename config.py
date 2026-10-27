"""FoxGuard yapılandırma dosyası - Güvenlik taraması, AI entegrasyonu ve sunucu ayarları."""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# Sunucu ayarları (sadece localhost)
HOST = os.environ.get("FOXGUARD_HOST", "127.0.0.1")
PORT = int(os.environ.get("FOXGUARD_PORT", "8765"))
DEBUG = os.environ.get("FOXGUARD_DEBUG", "false").lower() == "true"
SECRET_KEY = os.environ.get("FOXGUARD_SECRET", "foxguard-change-me-in-production")

# Yetkili kullanıcılar (SHA-256 şifre hash)
AUTHORIZED_USERS = {
    "ilkaycan": {
        "password_hash": "401fcfc43f067f4060c33bd01a8f7e3204be18700d46f22b997ee6599f204d39",
        "role": "owner",
    },
    "assistant": {
        "password_hash": "1a92642bef90e6aefcd06502592f3e0ccdd7141d4e88547ab308b7b80fccd76a",
        "role": "user",
    },
}

SESSION_TIMEOUT_MINUTES = int(os.environ.get("FOXGUARD_SESSION_TIMEOUT", "60"))

# Klasörler
QUARANTINE_DIR = BASE_DIR / "quarantine"
DOWNLOAD_DIR = BASE_DIR / "downloaded_projects"
STATIC_DIR = BASE_DIR / "static"
PLUGINS_DIR = BASE_DIR / "plugins"
REPORTS_DIR = BASE_DIR / "reports"
LOGS_DIR = BASE_DIR / "logs"

# AI entegrasyonu (yapay zeka ile kullanabilme)
AI_CONFIG = {
    "enabled": os.environ.get("FOXGUARD_AI_ENABLED", "true").lower() == "true",
    "api_base": os.environ.get("FOXGUARD_AI_API_BASE", "http://127.0.0.1:11434"),
    "api_key": os.environ.get("FOXGUARD_AI_API_KEY", ""),
    "model": os.environ.get("FOXGUARD_AI_MODEL", "beam-free"),
    "system_prompt": (
        "Sen FoxGuard güvenlik asistanısın. Kullanıcıların güvenlik taramaları, "
        "zararlı yazılım analizi, saldırı düzeyi raporları ve kod incelemeleri konusunda yardımcı ol."
    ),
}

# Şifreleme / Saldırı düzeyi
ATTACK_PATTERNS = {
    "critical": [
        r"os\.system\(", r"subprocess\.(run|call|Popen)\(", r"exec\(",
        r"pickle\.loads\(", r"yaml\.load\(", r"shell\s*=\s*True",
        r"rm\s+-rf\s+/", r"chmod\s+777", r"union\s+select", r"drop\s+table",
        r"\$\{.*\}", r"eval\(", r"__import__\(", r"socket\.", r"reverse\s+shell",
    ],
    "high": [
        r"SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*=.*['\"]\s*\+\s*", r"innerHTML\s*=",
        r"document\.write\(", r"<script", r"on\w+\s*=", r"import\s+requests\s*\n\s*.*\b(get|post)\(",
        r"urllib\.request\.urlopen\(", r"ftp://", r"telnet://",
    ],
    "medium": [
        r"open\(.*['\"].*['\"].*['\"]w['\"]", r"shutil\.rmtree\(", r"os\.remove\(",
        r"os\.unlink\(", r"chmod\s+", r"base64\.(b64decode|b64encode)\(", r"hashlib\.md5\(",
    ],
    "low": [
        r"print\(", r"input\(", r"open\(.*['\"]r['\"]", r"json\.(loads|dumps)\(",
    ],
}

SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 1,
}

ATTACK_LEVEL_LABELS = {
    "critical": "Kritik",
    "high": "Yüksek",
    "medium": "Orta",
    "low": "Düşük",
    "none": "Güvenli",
}

ATTACK_LEVEL_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#65a30d",
    "none": "#16a34a",
}

AUTO_SCAN_DOWNLOADED_PROJECTS = os.environ.get(
    "FOXGUARD_AUTO_SCAN", "true"
).lower() == "true"

# Klasörleri oluştur
def ensure_dirs():
    for d in [QUARANTINE_DIR, DOWNLOAD_DIR, STATIC_DIR, PLUGINS_DIR, REPORTS_DIR, LOGS_DIR]:
        d.mkdir(parents=True, exist_ok=True)

def ensure_files():
    """Gerekli dosyaların var olmasını sağla."""
    # users.json yoksa oluştur
    users_file = BASE_DIR / "users.json"
    if not users_file.exists():
        import json
        with open(users_file, "w", encoding="utf-8") as f:
            json.dump(AUTHORIZED_USERS, f, ensure_ascii=False, indent=2)
