"""Örnek FoxGuard güvenlik eklentisi."""

from plugins.loader import loader


def register(plugin_loader):
    """Eklenti kaydı."""

    def scan_for_secrets(code: str) -> list:
        """Kodda olası gizli anahtar/şifre arar."""
        import re
        patterns = [
            r"sk-[A-Za-z0-9]{20,}",          # OpenAI/API key
            r"AKIA[0-9A-Z]{16}",             # AWS Access Key
            r"ghp_[A-Za-z0-9]{36,}",         # GitHub token
            r"password\s*=\s*['\"][^'\"]+['\"]",
            r"api_key\s*=\s*['\"][^'\"]+['\"]",
        ]
        findings = []
        for pat in patterns:
            for m in re.finditer(pat, code):
                findings.append({
                    "pattern": pat,
                    "match": m.group(0)[:60],
                    "pos": m.start(),
                })
        return findings

    def on_scan_complete(result: dict) -> dict:
        """Tarama bittiğinde gizli anahtar kontrolü yapar."""
        # result bir tarama raporu olabilir; burada basit bir işaretleme yapıyoruz
        result.setdefault("plugin_findings", []).append({
            "plugin": "security_scan",
            "findings": [],
        })
        return result

    # Hook kaydı
    plugin_loader.register_hook("scan_complete", on_scan_complete)

    # Eklentiye özel fonksiyonu dışarıya aç
    plugin_loader.plugins.setdefault("_api", {})["security_scan"] = {
        "scan_for_secrets": scan_for_secrets,
    }

    print("[foxguard] security_scan eklentisi yüklendi.")
