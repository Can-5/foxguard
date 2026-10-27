"""FoxGuard güvenlik ve virüs tarama motoru."""

import os
import re
import hashlib
import json
from datetime import datetime
from config import (
    SCAN_PATHS,
    MALWARE_SIGNATURES,
    ATTACK_PATTERNS,
    SIGNATURES_DB,
    QUARANTINE_DIR,
    ensure_dirs,
    SEVERITY_WEIGHTS,
    ATTACK_LEVEL_LABELS,
)


def _file_hash(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
    except Exception:
        return ""
    return h.hexdigest()


# Kritik saldırı kalıpları (bu kalıplarla eşleşen içerik critical seviyesindedir)
_CRITICAL_PATTERNS = [
    r"os\.system\s*\(",
    r"subprocess\.",
    r"exec\s*\(",
    r"pickle\.loads\s*\(",
    r"yaml\.load\s*\(",
    r"shell\s*=\s*True",
    r"rm\s+-rf\s+",
    r"chmod\s+777",
    r"union\s+select",
    r"drop\s+table",
    r"\$\{.*\}",
]

# Yüksek riskli saldırı kalıpları
_HIGH_PATTERNS = [
    r"<script",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"eval\s*\(",
    r"document\.cookie",
    r"\.\./\.\./",
    r"/etc/passwd",
    r"cmd\.exe",
    r"/bin/sh",
    r"nc\s+-",
    r"ncat\s+-",
]


def _severity_for_pattern(pat: str) -> str:
    """Bir saldırı kalıbına göre severity döndürür (critical > high > medium > low)."""
    import re as _re
    for cp in _CRITICAL_PATTERNS:
        if _re.search(cp, pat, _re.IGNORECASE):
            return "critical"
    for hp in _HIGH_PATTERNS:
        if _re.search(hp, pat, _re.IGNORECASE):
            return "high"
    return "medium"


def calculate_attack_level(threats: list) -> str:
    """Tehdit listesinden genel saldırı düzeyini hesaplar:
    clean < düşük < orta < yüksek < critical."""
    level = "clean"
    for t in threats:
        sev = t.get("severity", "low")
        if SEVERITY_WEIGHTS.get(sev, 1) > SEVERITY_WEIGHTS.get(level, 1):
            level = sev
    return ATTACK_LEVEL_LABELS.get(level, "düşük")


def _scan_text_content(path: str, patterns: list) -> list:
    """Dosya içeriğini verilen kalıp listesiyle tarar, eşleşenleri döndürür."""
    hits = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        for pat in patterns:
            try:
                for m in re.finditer(pat, content, re.IGNORECASE):
                    hits.append({
                        "pattern": pat,
                        "match": m.group(0)[:120],
                        "pos": m.start(),
                    })
            except re.error:
                # Kalıp derlenemezse düz metin ara
                if pat.lower() in content.lower():
                    hits.append({"pattern": pat, "match": pat, "pos": -1})
    except Exception:
        pass
    return hits


def scan_path(target_path: str) -> dict:
    """Tek bir dosya veya dizini tarar."""
    ensure_dirs()
    result = {
        "path": target_path,
        "scanned_at": datetime.now().isoformat(),
        "threats": [],
        "files_scanned": 0,
        "status": "clean",
    }

    if not os.path.exists(target_path):
        result["status"] = "not_found"
        return result

    if os.path.isfile(target_path):
        files = [target_path]
    else:
        files = []
        for root, _dirs, fnames in os.walk(target_path):
            for fn in fnames:
                files.append(os.path.join(root, fn))

    for fpath in files:
        result["files_scanned"] += 1

        # 1. Dosya adı imzası
        fname = os.path.basename(fpath).lower()
        for sig in MALWARE_SIGNATURES:
            if sig in fname:
                result["threats"].append({
                    "file": fpath,
                    "type": "malware_signature",
                    "severity": "high",
                    "detail": f"Dosya adı imzası eşleşti: {sig}",
                    "hash": _file_hash(fpath),
                })
                break

        # 2. İçerik taraması (sadece küçük metin dosyaları)
        try:
            if os.path.getsize(fpath) < 5_000_000:  # 5 MB sınırı
                hits = _scan_text_content(fpath, MALWARE_SIGNATURES + [p for p in ATTACK_PATTERNS])
                if hits:
                    # En ağır severity'yi hesapla
                    worst = "low"
                    for h in hits:
                        sev = _severity_for_pattern(h["pattern"])
                        if SEVERITY_WEIGHTS.get(sev, 1) > SEVERITY_WEIGHTS.get(worst, 1):
                            worst = sev
                    result["threats"].append({
                        "file": fpath,
                        "type": "content_match",
                        "severity": worst,
                        "detail": f"{len(hits)} kalıp eşleşti (en ağır: {ATTACK_LEVEL_LABELS.get(worst, 'düşük')})",
                        "hits": hits[:10],
                        "hash": _file_hash(fpath),
                    })
        except Exception:
            pass

    # Genel saldırı düzeyini hesapla
    result["attack_level"] = calculate_attack_level(result["threats"])

    if result["threats"]:
        result["status"] = "threats_found"

    return result


def scan_all() -> dict:
    """Tüm yapılandırılmış yolları tarar."""
    ensure_dirs()
    report = {
        "scanned_at": datetime.now().isoformat(),
        "total_files": 0,
        "total_threats": 0,
        "paths": [],
        "status": "clean",
    }

    all_threats = []
    for path in SCAN_PATHS:
        if os.path.exists(path):
            pr = scan_path(path)
            report["paths"].append(pr)
            report["total_files"] += pr["files_scanned"]
            report["total_threats"] += len(pr["threats"])
            all_threats.extend(pr["threats"])
            if pr["status"] != "clean":
                report["status"] = "threats_found"

    # Genel saldırı düzeyini tüm tehditlerden hesapla
    report["attack_level"] = calculate_attack_level(all_threats)

    return report


def quarantine_file(filepath: str) -> str:
    """Tehdit dosyasını karantinaya alır."""
    ensure_dirs()
    fname = os.path.basename(filepath)
    dest = os.path.join(QUARANTINE_DIR, fname)
    # Çakışma varsa süre ekle
    if os.path.exists(dest):
        base, ext = os.path.splitext(fname)
        dest = os.path.join(QUARANTINE_DIR, f"{base}_{int(__import__('time').time())}{ext}")
    try:
        import shutil
        shutil.move(filepath, dest)
        return dest
    except Exception as e:
        return f"ERROR: {e}"


def delete_file(filepath: str) -> str:
    """Tehdit dosyasını kalıcı olarak siler."""
    try:
        os.remove(filepath)
        return "deleted"
    except Exception as e:
        return f"ERROR: {e}"


def list_quarantined() -> list:
    """Karantinadaki dosyaları listeler."""
    ensure_dirs()
    if not os.path.exists(QUARANTINE_DIR):
        return []
    files = []
    for fn in os.listdir(QUARANTINE_DIR):
        fp = os.path.join(QUARANTINE_DIR, fn)
        if os.path.isfile(fp):
            files.append({
                "name": fn,
                "path": fp,
                "size": os.path.getsize(fp),
            })
    return files


def restore_from_quarantine(filename: str) -> str:
    """Karantinadan dosyayı geri yükler (kullanıcı onayıyla)."""
    src = os.path.join(QUARANTINE_DIR, filename)
    if not os.path.exists(src):
        return "not_found"
    # Güvenlik: sadece quarantine klasöründeki dosyalar geri yüklenebilir
    try:
        import shutil
        # Orijinal konumu bilmiyoruz, mevcut dizine kopyala
        dest = os.path.join(os.path.dirname(QUARANTINE_DIR), "restored", filename)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(src, dest)
        return dest
    except Exception as e:
        return f"ERROR: {e}"
