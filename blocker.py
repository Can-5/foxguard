"""FoxGuard saldırı engelleme katmanı."""

import re
from config import ATTACK_PATTERNS


class RequestBlocker:
    """Gelen istekleri saldırı kalıpları karşı taranıp engeller."""

    def __init__(self):
        self.compiled = []
        for pat in ATTACK_PATTERNS:
            try:
                self.compiled.append(re.compile(pat, re.IGNORECASE))
            except re.error:
                pass

    def is_safe(self, text: str) -> tuple:
        """Metin güvenli mi? (bool, reason) döndürür."""
        if not text:
            return True, ""
        for cp in self.compiled:
            m = cp.search(text)
            if m:
                return False, f"Saldırı kalıbı tespit edildi: {cp.pattern[:60]}"
        return True, ""

    def check_headers(self, headers: dict) -> tuple:
        """HTTP başlıklarını kontrol eder."""
        for key, val in headers.items():
            safe, reason = self.is_safe(val)
            if not safe:
                return False, f"{key}: {reason}"
        return True, ""

    def check_form(self, form: dict) -> tuple:
        """Form alanlarını kontrol eder."""
        for key, val in form.items():
            safe, reason = self.is_safe(str(val))
            if not safe:
                return False, f"{key}: {reason}"
        return True, ""
