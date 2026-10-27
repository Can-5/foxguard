"""Kimlik doğrulama modülü - SHA-256 şifre hash, session yönetimi."""

import time
import hashlib
from functools import wraps
from flask import session, redirect, url_for, flash, request
from config import AUTHORIZED_USERS, SESSION_TIMEOUT_MINUTES


def _hash_password(password: str) -> str:
    """Şifreyi SHA-256 ile hashle."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def initialize_users():
    """Kullanıcı verilerini doğrula ve session'ı başlat."""
    for username, data in AUTHORIZED_USERS.items():
        if "password_hash" not in data:
            # İlk kurulum: plain_password'dan hash üret
            plain = data.get("plain_password", "")
            data["password_hash"] = _hash_password(plain)


def authenticate(username: str, password: str) -> bool:
    """Kullanıcı adı ve şifreyi doğrula."""
    user = AUTHORIZED_USERS.get(username)
    if not user:
        return False
    expected_hash = user.get("password_hash", "")
    if not expected_hash:
        return False
    return _hash_password(password) == expected_hash


def is_authenticated() -> bool:
    """Kullanıcı oturumunda mı ve session süresi dolmamış mı kontrol et."""
    if not session.get("authenticated"):
        return False
    login_time = session.get("login_time", 0)
    if login_time == 0:
        return False
    elapsed = time.time() - login_time
    if elapsed > SESSION_TIMEOUT_MINUTES * 60:
        logout()
        return False
    return True


def login_required(f):
    """Route koruma dekoratörü."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_authenticated():
            flash("Lütfen giriş yapın.", "warning")
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated


def get_current_user() -> str:
    """Mevcut oturumdaki kullanıcı adını döndür."""
    return session.get("username", "")


def get_user_role() -> str:
    """Mevcut kullanıcının rolünü döndür."""
    user = AUTHORIZED_USERS.get(get_current_user(), {})
    return user.get("role", "guest")


def logout():
    """Oturumu sonlandır."""
    session.clear()


def get_all_users() -> dict:
    """Tüm kullanıcıları (hash hariç) döndür."""
    result = {}
    for username, data in AUTHORIZED_USERS.items():
        result[username] = {
            "role": data.get("role", "guest"),
        }
    return result
