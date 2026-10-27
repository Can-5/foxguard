"""FoxGuard web arayüzü - Flask tabanlı, sadece localhost.
WordPress benzeri eklenti sistemi, proje kod indirici, web sitesi embed desteği,
modern Tailwind arayüzü ve yapay zeka entegrasyonu ile.
"""

import os
import json
import time
from datetime import datetime
from flask import (
    Flask, render_template_string, request, redirect, url_for,
    session, jsonify, flash, send_from_directory
)
from config import (
    HOST, PORT, DEBUG, SECRET_KEY,
    AUTHORIZED_USERS, QUARANTINE_DIR, ensure_dirs, BASE_DIR,
    AUTO_SCAN_DOWNLOADED_PROJECTS, AI_CONFIG, ATTACK_PATTERNS,
    SEVERITY_WEIGHTS, ATTACK_LEVEL_LABELS, ATTACK_LEVEL_COLORS,
    REPORTS_DIR, LOGS_DIR, DOWNLOAD_DIR, ensure_files,
)
from auth import (
    initialize_users, authenticate, is_authenticated,
    login_required, get_current_user, get_user_role, logout,
    get_all_users,
)
from scanner import scan_all, scan_path, quarantine_file, delete_file, list_quarantined, restore_from_quarantine, calculate_attack_level
from blocker import RequestBlocker
from reporter import format_scan_report, format_virus_alert
from plugins.loader import loader as plugin_loader
from project_downloader import downloader
from embed import get_embed_html

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.secret_key = SECRET_KEY
blocker = RequestBlocker()

# Eklentileri yükle
plugin_loader.load_all()

# embed.js'yi statik klasöre kaydet
embed_static = os.path.join(BASE_DIR, "foxguard", "static")
from embed import save_embed_js
save_embed_js(embed_static)

# ---- Kimlik doğrulama rotaları ----

@app.route("/login", methods=["GET", "POST"])
def login():
    if is_authenticated():
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        safe, reason = blocker.is_safe(username + password)
        if not safe:
            flash("Girdiğiniz bilgilerde güvenlik riski tespit edildi.", "error")
            return render_template_string(LOGIN_HTML, error=reason)

        if authenticate(username, password):
            session["authenticated"] = True
            session["username"] = username
            session["login_time"] = time.time()
            flash(f"Hoş geldiniz, {username}!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Kullanıcı adı veya şifre hatalı.", "error")
    return render_template_string(LOGIN_HTML)


@app.route("/logout")
@login_required
def do_logout():
    logout()
    flash("Çıkış yapıldı.", "info")
    return redirect(url_for("login"))


# ---- Ana sayfa / Dashboard ----

@app.route("/")
@login_required
def dashboard():
    plugins_info = plugin_loader.get_info()
    return render_template_string(
        DASHBOARD_HTML,
        user=get_current_user(),
        role=get_user_role(),
        plugins=plugins_info,
    )


# ---- Tarama rotaları ----

@app.route("/scan", methods=["GET", "POST"])
@login_required
def scan():
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        if not target:
            flash("Lütfen bir dosya yolu veya dizin girin.", "error")
            return redirect(url_for("scan"))
        result = scan_path(target)
        result["timestamp"] = datetime.now().isoformat()
        return render_template_string(
            SCAN_RESULT_HTML,
            result=result,
            user=get_current_user(),
        )
    return render_template_string(SCAN_HTML, user=get_current_user())


@app.route("/scan/project", methods=["POST"])
@login_required
def scan_project():
    """Dosya yolu veya GitHub URL ile proje tarama (şifreyle korumalı)."""
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "Hedef belirtilmedi."}), 400

    if target.startswith("http://") or target.startswith("https://"):
        # GitHub URL ise indirip tara
        downloader.download_zip(target)
        # İndirilen dizini bul
        repo_name = target.rstrip("/").split("/")[-1]
        extracted = DOWNLOAD_DIR / repo_name
        if not extracted.exists():
            extracted = DOWNLOAD_DIR / (repo_name + "-main")
        if not extracted.exists():
            extracted = DOWNLOAD_DIR / (repo_name + "-master")
        if extracted.exists():
            result = scan_path(str(extracted))
            result["auto_scanned"] = True
            result["source"] = "github"
            result["url"] = target
            return jsonify(result)
        return jsonify({"error": "Proje indirilemedi veya bulunamadı."}), 404
    else:
        result = scan_path(target)
        result["auto_scanned"] = False
        result["source"] = "local"
        return jsonify(result)


@app.route("/scan/report", methods=["GET"])
@login_required
def scan_report():
    return render_template_string(REPORT_HTML, user=get_current_user())


# ---- API: eylem ----

@app.route("/api/action", methods=["POST"])
@login_required
def api_action():
    data = request.get_json(silent=True) or {}
    action = data.get("action", "")
    filename = data.get("filename", "")

    if action == "quarantine" and filename:
        quarantine_file(filename)
        return jsonify({"status": "ok", "message": f"{filename} karantinaya alındı."})
    if action == "delete" and filename:
        delete_file(filename)
        return jsonify({"status": "ok", "message": f"{filename} silindi."})
    if action == "restore" and filename:
        restore_from_quarantine(filename)
        return jsonify({"status": "ok", "message": f"{filename} geri yüklendi."})
    return jsonify({"error": "Geçersiz eylem."}), 400


# ---- Virüs uyarı ----

@app.route("/virus/alert", methods=["GET"])
@login_required
def virus_alert():
    return render_template_string(VIRUS_ALERT_HTML, user=get_current_user())


@app.route("/api/virus/scan", methods=["POST"])
@login_required
def api_virus_scan():
    data = request.get_json(silent=True) or {}
    path = data.get("path", "")
    result = scan_path(path)
    return jsonify(result)


# ---- Karantina ----

@app.route("/quarantine", methods=["GET"])
@login_required
def quarantine():
    items = list_quarantined()
    return render_template_string(QUARANTINE_HTML, items=items, user=get_current_user())


@app.route("/quarantine/restore/<filename>", methods=["POST"])
@login_required
def quarantine_restore(filename):
    restore_from_quarantine(filename)
    flash(f"{filename} karantinadan geri yüklendi.", "success")
    return redirect(url_for("quarantine"))


# ---- Eklentiler ----

@app.route("/plugins", methods=["GET"])
@login_required
def plugins():
    info = plugin_loader.get_info()
    return render_template_string(PLUGINS_HTML, plugins=info, user=get_current_user())


@app.route("/plugins/reload", methods=["POST"])
@login_required
def plugins_reload():
    plugin_loader.load_all()
    flash("Eklentiler yeniden yüklendi.", "success")
    return redirect(url_for("plugins"))


# ---- Proje indirici ----

@app.route("/projects", methods=["GET"])
@login_required
def projects():
    repos = downloader.list_github_repos()
    return render_template_string(PROJECTS_HTML, repos=repos, user=get_current_user())


@app.route("/projects/github/repos", methods=["GET"])
@login_required
def api_github_repos():
    return jsonify(downloader.list_github_repos())


@app.route("/projects/download", methods=["POST"])
@login_required
def projects_download():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL gerekli."}), 400
    result = downloader.download_zip(url)
    if AUTO_SCAN_DOWNLOADED_PROJECTS and result.get("success"):
        repo_name = url.rstrip("/").split("/")[-1]
        extracted = DOWNLOAD_DIR / repo_name
        if not extracted.exists():
            extracted = DOWNLOAD_DIR / (repo_name + "-main")
        if not extracted.exists():
            extracted = DOWNLOAD_DIR / (repo_name + "-master")
        if extracted.exists():
            scan = scan_path(str(extracted))
            result["scan"] = scan
            result["attack_level"] = scan.get("attack_level", "none")
    return jsonify(result)


# ---- Embed ----

@app.route("/embed", methods=["GET"])
def embed_page():
    return render_template_string(EMBED_PAGE_HTML)


@app.route("/static/embed.js", methods=["GET"])
def embed_js():
    return send_from_directory(embed_static, "embed.js", mimetype="application/javascript")


@app.route("/api/embed/status", methods=["GET"])
def embed_status():
    return jsonify({"status": "ok", "plugins": len(plugin_loader.plugins)})


# ---- Yapay Zeka entegrasyonu ----

@app.route("/api/ai/chat", methods=["POST"])
@login_required
def ai_chat():
    """Yapay zeka sohbet endpoint'i."""
    if not AI_CONFIG["enabled"]:
        return jsonify({"error": "AI entegrasyonu devre dışı."}), 403

    data = request.get_json(silent=True) or {}
    message = data.get("message", "").strip()
    if not message:
        return jsonify({"error": "Mesaj boş."}), 400

    # Güvenlik kontrolü
    safe, reason = blocker.is_safe(message)
    if not safe:
        return jsonify({"error": f"Güvenlik riski: {reason}"}), 400

    # Ollama / OpenAI uyumlu API'ye istek
    try:
        import urllib.request
        payload = {
            "model": AI_CONFIG["model"],
            "messages": [
                {"role": "system", "content": AI_CONFIG["system_prompt"]},
                {"role": "user", "content": message},
            ],
            "stream": False,
        }
        req = urllib.request.Request(
            f"{AI_CONFIG['api_base']}/v1/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {AI_CONFIG.get('api_key','')}"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode("utf-8"))
        answer = result.get("choices", [{}])[0].get("message", {}).get("content", "Yanıt alınamadı.")
        return jsonify({"response": answer, "model": AI_CONFIG["model"]})
    except Exception as e:
        return jsonify({"error": f"AI API hatası: {str(e)}"}), 500


@app.route("/api/ai/analyze", methods=["POST"])
@login_required
def ai_analyze():
    """Yapay zeka ile güvenlik taraması analizi."""
    if not AI_CONFIG["enabled"]:
        return jsonify({"error": "AI entegrasyonu devre dışı."}), 403

    data = request.get_json(silent=True) or {}
    scan_result = data.get("scan_result", {})
    if not scan_result:
        return jsonify({"error": "Tarama sonucu gerekli."}), 400

    prompt = (
        "Aşağıdaki güvenlik taramasını analiz et ve Türkçe olarak özetle, "
        "riskleri değerlendir ve öneriler sun:\n\n"
        f"{json.dumps(scan_result, ensure_ascii=False, indent=2)}"
    )

    try:
        import urllib.request
        payload = {
            "model": AI_CONFIG["model"],
            "messages": [
                {"role": "system", "content": AI_CONFIG["system_prompt"]},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
        }
        req = urllib.request.Request(
            f"{AI_CONFIG['api_base']}/v1/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {AI_CONFIG.get('api_key','')}"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode("utf-8"))
        answer = result.get("choices", [{}])[0].get("message", {}).get("content", "Yanıt alınamadı.")
        return jsonify({"analysis": answer, "model": AI_CONFIG["model"]})
    except Exception as e:
        return jsonify({"error": f"AI API hatası: {str(e)}"}), 500


@app.route("/api/ai/status", methods=["GET"])
@login_required
def ai_status():
    return jsonify({
        "enabled": AI_CONFIG["enabled"],
        "model": AI_CONFIG["model"],
        "api_base": AI_CONFIG["api_base"],
    })


# ============================================================
# HTML Şablonlar (Tailwind CSS, dark mode, responsive)
# ============================================================

LOGIN_HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FoxGuard Giriş</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
body { font-family: 'Inter', sans-serif; }
</style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen flex items-center justify-center">
<div class="w-full max-w-md p-4">
  <div class="bg-slate-900 border border-slate-700 rounded-xl p-8 shadow-2xl">
    <div class="flex items-center gap-3 mb-6">
      <div class="w-10 h-10 bg-emerald-500 rounded-lg flex items-center justify-center text-white">
        🦊
      </div>
      <h1 class="text-xl font-bold text-emerald-400">FoxGuard</h1>
      <span class="ml-auto text-xs text-slate-500">v2.0</span>
    </div>

    {% if error %}
    <div class="bg-red-900/20 border border-red-500/30 text-red-400 px-4 py-3 rounded-lg mb-6 text-sm">{{ error }}</div>
    {% endif %}

    <form method="POST" class="space-y-4">
      <div>
        <label class="block text-sm font-medium text-slate-300 mb-1">Kullanıcı Adı</label>
        <input type="text" name="username" required
          class="w-full bg-slate-800 border border-slate-600 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-transparent transition-all">
      </div>
      <div>
        <label class="block text-sm font-medium text-slate-300 mb-1">Şifre</label>
        <input type="password" name="password" required
          class="w-full bg-slate-800 border border-slate-600 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-transparent transition-all">
      </div>
      <button type="submit"
        class="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-semibold py-3 rounded-lg transition-all shadow-lg shadow-emerald-900/20">
        Giriş Yap
      </button>
    </form>

    <div class="mt-6 pt-6 border-t border-slate-700 text-xs text-slate-500 text-center">
      Sadece <code>127.0.0.1</code> erişimi açık.<br>
      Dış ağ kapalı.
    </div>
  </div>
</div>
</body>
</html>"""


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FoxGuard - Kontrol Paneli</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
body { font-family: 'Inter', sans-serif; }
</style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen">
  <!-- Topbar -->
  <nav class="bg-slate-900 border-b border-slate-700 sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="w-8 h-8 bg-emerald-500 rounded-lg flex items-center justify-center text-white">🦊</div>
        <span class="font-bold text-lg text-emerald-400">FoxGuard</span>
      </div>
      <div class="flex items-center gap-4">
        <span class="text-sm text-slate-400">{{ user }} <span class="px-2 py-0.5 bg-slate-800 rounded text-xs">{{ role }}</span></span>
        <a href="/logout" class="text-slate-400 hover:text-white transition">Çıkış</a>
      </div>
    </div>
  </nav>

  <div class="max-w-7xl mx-auto px-4 py-8">
    <!-- Flash mesajları -->
    {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
    <div class="mb-6">
      {% for category, message in messages %}
      <div class="p-4 rounded-lg mb-3 {% if category == 'error' %}bg-red-900/20 border border-red-500/30 text-red-400{% elif category == 'success' %}bg-emerald-900/20 border border-emerald-500/30 text-emerald-400{% elif category == 'warning' %}bg-amber-900/20 border border-amber-500/30 text-amber-400{% else %}bg-blue-900/20 border border-blue-500/30 text-blue-400{% endif %}">
        {{ message }}
      </div>
      {% endfor %}
    </div>
    {% endif %}
    {% endwith %}

    <!-- Kartlar grid -->
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
      <div class="bg-slate-900 border border-slate-700 rounded-xl p-6">
        <h3 class="text-sm font-semibold text-slate-400 mb-1">Güvenlik Durumu</h3>
        <p class="text-2xl font-bold text-emerald-400">Aktif</p>
        <p class="text-xs text-slate-500 mt-2">Sadece localhost erişimi</p>
      </div>
      <div class="bg-slate-900 border border-slate-700 rounded-xl p-6">
        <h3 class="text-sm font-semibold text-slate-400 mb-1">Eklentiler</h3>
        <p class="text-2xl font-bold text-blue-400">{{ plugins|length }}</p>
        <p class="text-xs text-slate-500 mt-2">Yüklü eklenti sayısı</p>
      </div>
      <div class="bg-slate-900 border border-slate-700 rounded-xl p-6">
        <h3 class="text-sm font-semibold text-slate-400 mb-1">AI Entegrasyonu</h3>
        <p class="text-2xl font-bold text-purple-400">Hazır</p>
        <p class="text-xs text-slate-500 mt-2">Yapay zeka sohbet ve analiz</p>
      </div>
    </div>

    <!-- Özellik kartları -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
      <!-- Proje Tarama Kartı -->
      <div class="bg-slate-900 border border-slate-700 rounded-xl p-6 hover:border-emerald-500/50 transition">
        <div class="flex items-center gap-3 mb-6">
          <div class="w-10 h-10 bg-emerald-500/20 rounded-lg flex items-center justify-center text-emerald-400">🔗</div>
          <h2 class="text-lg font-bold text-slate-100">Proje URL / Dosya Tarama</h2>
        </div>
        <p class="text-slate-400 text-sm mb-6">Bir dosya yolu veya GitHub repository URL'si girerek projeyi tarayın. Şifreyle korumalı işlemdir.</p>
        <div class="space-y-3">
          <input type="text" id="scanTarget" placeholder="https://github.com/owner/repo veya /dosya/yolu"
            class="w-full bg-slate-800 border border-slate-600 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-emerald-500">
          <button onclick="scanProject()" class="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-semibold py-3 rounded-lg transition shadow-lg shadow-emerald-900/20">
            Tara
          </button>
        </div>
        <div id="scanResult" class="mt-4 hidden"></div>
      </div>

      <!-- AI Sohbet Kartı -->
      <div class="bg-slate-900 border border-slate-700 rounded-xl p-6 hover:border-purple-500/50 transition">
        <div class="flex items-center gap-3 mb-6">
          <div class="w-10 h-10 bg-purple-500/20 rounded-lg flex items-center justify-center text-purple-400">🤖</div>
          <h2 class="text-lg font-bold text-slate-100">Yapay Zeka Asistanı</h2>
        </div>
        <p class="text-slate-400 text-sm mb-6">Güvenlik taramalarınızı analiz etmek, kod inceleme yapmak ve öneri almak için AI asistanıyla sohbet edin.</p>
        <div class="space-y-3">
          <input type="text" id="aiMessage" placeholder="Mesajınızı yazın..."
            class="w-full bg-slate-800 border border-slate-600 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-purple-500">
          <button onclick="aiChat()" class="w-full bg-purple-600 hover:bg-purple-500 text-white font-semibold py-3 rounded-lg transition shadow-lg shadow-purple-900/20">
            Gönder
          </button>
        </div>
        <div id="aiResult" class="mt-4 hidden p-4 bg-slate-800 rounded-lg text-sm"></div>
      </div>
    </div>

    <!-- Eklenti listesi -->
    <div class="bg-slate-900 border border-slate-700 rounded-xl p-6">
      <h2 class="text-lg font-bold text-slate-100 mb-4">Eklentiler</h2>
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead>
            <tr class="text-slate-400 border-b border-slate-700">
              <th class="pb-2 text-left">Ad</th>
              <th class="pb-2 text-left">Durum</th>
              <th class="pb-2 text-left">Açıklama</th>
            </tr>
          </thead>
          <tbody>
            {% for name, info in plugins.items() %}
            <tr class="border-b border-slate-800 hover:bg-slate-800/50 transition">
              <td class="py-2 text-slate-200">{{ name }}</td>
              <td class="py-2"><span class="px-2 py-0.5 bg-emerald-900/20 text-emerald-400 rounded text-xs">Aktif</span></td>
              <td class="py-2 text-slate-400">{{ info.get('description','') }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <script>
  async function scanProject() {
    const target = document.getElementById('scanTarget').value;
    const resultDiv = document.getElementById('scanResult');
    resultDiv.classList.remove('hidden');
    resultDiv.innerHTML = '<div class="p-4 bg-slate-800 rounded-lg text-slate-400 text-sm">Taranıyor...</div>';

    try {
      const res = await fetch('/scan/project', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({target: target})
      });
      const data = await res.json();

      let levelColor = '#16a34a';
      if (data.attack_level === 'critical') levelColor = '#dc2626';
      else if (data.attack_level === 'high') levelColor = '#ea580c';
      else if (data.attack_level === 'medium') levelColor = '#d97706';
      else if (data.attack_level === 'low') levelColor = '#65a30d';

      resultDiv.innerHTML = `
        <div class="p-4 bg-slate-800 rounded-lg border border-slate-600">
          <div class="flex justify-between items-start mb-2">
            <span class="text-slate-300 font-medium">Saldırı Düzeyi:</span>
            <span class="text-xs font-bold px-2 py-0.5 rounded" style="background:${levelColor};color:white">${data.attack_level || 'none'}</span>
          </div>
          <div class="text-slate-400 text-sm mt-2">${data.status || 'Tarama tamamlandı'}</div>
        </div>
      `;
    } catch (e) {
      resultDiv.innerHTML = '<div class="p-4 bg-red-900/20 border border-red-500/30 text-red-400 rounded-lg text-sm">Hata: ' + e.message + '</div>';
    }
  }

  async function aiChat() {
    const message = document.getElementById('aiMessage').value;
    const resultDiv = document.getElementById('aiResult');
    resultDiv.classList.remove('hidden');
    resultDiv.innerHTML = '<div class="p-4 bg-slate-800 rounded-lg text-slate-400 text-sm">Yanıtlanıyor...</div>';

    try {
      const res = await fetch('/api/ai/chat', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({message: message})
      });
      const data = await res.json();
      resultDiv.innerHTML = '<div class="p-4 bg-slate-800 rounded-lg border border-slate-600"><div class="text-slate-300 text-sm">' + (data.response || data.error) + '</div></div>';
    } catch (e) {
      resultDiv.innerHTML = '<div class="p-4 bg-red-900/20 border border-red-500/30 text-red-400 rounded-lg text-sm">Hata: ' + e.message + '</div>';
    }
  }
  </script>
</body>
</html>"""


SCAN_HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FoxGuard - Tarama</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
body { font-family: 'Inter', sans-serif; }
</style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen">
  <nav class="bg-slate-900 border-b border-slate-700 sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="w-8 h-8 bg-emerald-500 rounded-lg flex items-center justify-center text-white">🦊</div>
        <span class="font-bold text-lg text-emerald-400">FoxGuard</span>
      </div>
      <div class="flex items-center gap-4">
        <span class="text-sm text-slate-400">{{ user }}</span>
        <a href="/" class="text-slate-400 hover:text-white">Geri</a>
        <a href="/logout" class="text-slate-400 hover:text-white">Çıkış</a>
      </div>
    </div>
  </nav>

  <div class="max-w-2xl mx-auto px-4 py-8">
    <h1 class="text-2xl font-bold mb-6">Güvenlik Taraması</h1>
    <form method="POST" class="bg-slate-900 border border-slate-700 rounded-xl p-6">
      <div class="mb-4">
        <label class="block text-sm font-medium text-slate-300 mb-2">Dosya Yolu veya Dizin</label>
        <input type="text" name="target" placeholder="/home/ilkaycan/proje" required
          class="w-full bg-slate-800 border border-slate-600 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-emerald-500">
      </div>
      <button type="submit" class="bg-emerald-600 hover:bg-emerald-500 text-white font-semibold py-3 rounded-lg transition shadow-lg">
        Tara
      </button>
    </form>
  </div>
</body>
</html>"""


SCAN_RESULT_HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FoxGuard - Tarama Sonucu</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
body { font-family: 'Inter', sans-serif; }
</style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen">
  <nav class="bg-slate-900 border-b border-slate-700 sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="w-8 h-8 bg-emerald-500 rounded-lg flex items-center justify-center text-white">🦊</div>
        <span class="font-bold text-lg text-emerald-400">FoxGuard</span>
      </div>
      <div class="flex items-center gap-4">
        <span class="text-sm text-slate-400">{{ user }}</span>
        <a href="/scan" class="text-slate-400 hover:text-white">Yeni Tarama</a>
        <a href="/logout" class="text-slate-400 hover:text-white">Çıkış</a>
      </div>
    </div>
  </nav>

  <div class="max-w-4xl mx-auto px-4 py-8">
    <h1 class="text-2xl font-bold mb-6">Tarama Sonucu</h1>
    <div class="bg-slate-900 border border-slate-700 rounded-xl p-6">
      <div class="flex justify-between items-start mb-4">
        <span class="text-slate-300 font-medium">Saldırı Düzeyi:</span>
        <span class="text-xs font-bold px-2 py-0.5 rounded" style="background:{{ ATTACK_LEVEL_COLORS.get(result.get('attack_level','none'), '#16a34a') }};color:white">
          {{ ATTACK_LEVEL_LABELS.get(result.get('attack_level','none'), 'Bilinmiyor') }}
        </span>
      </div>
      <pre class="bg-slate-800 p-4 rounded-lg text-sm overflow-x-auto">{{ result|tojson }}</pre>
    </div>
  </div>
</body>
</html>"""


REPORT_HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FoxGuard - Rapor</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
body { font-family: 'Inter', sans-serif; }
</style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen">
  <nav class="bg-slate-900 border-b border-slate-700 sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="w-8 h-8 bg-emerald-500 rounded-lg flex items-center justify-center text-white">🦊</div>
        <span class="font-bold text-lg text-emerald-400">FoxGuard</span>
      </div>
      <div class="flex items-center gap-4">
        <span class="text-sm text-slate-400">{{ user }}</span>
        <a href="/" class="text-slate-400 hover:text-white">Geri</a>
        <a href="/logout" class="text-slate-400 hover:text-white">Çıkış</a>
      </div>
    </div>
  </nav>

  <div class="max-w-4xl mx-auto px-4 py-8">
    <h1 class="text-2xl font-bold mb-6">Güvenlik Raporu</h1>
    <div class="bg-slate-900 border border-slate-700 rounded-xl p-6">
      {{ format_scan_report()|safe }}
    </div>
  </div>
</body>
</html>"""


VIRUS_ALERT_HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FoxGuard - Virüs Uyarısı</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
body { font-family: 'Inter', sans-serif; }
</style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen">
  <nav class="bg-slate-900 border-b border-slate-700 sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="w-8 h-8 bg-red-500 rounded-lg flex items-center justify-center text-white">🦊</div>
        <span class="font-bold text-lg text-red-400">FoxGuard</span>
      </div>
      <div class="flex items-center gap-4">
        <span class="text-sm text-slate-400">{{ user }}</span>
        <a href="/" class="text-slate-400 hover:text-white">Geri</a>
        <a href="/logout" class="text-slate-400 hover:text-white">Çıkış</a>
      </div>
    </div>
  </nav>

  <div class="max-w-3xl mx-auto px-4 py-8">
    <h1 class="text-2xl font-bold text-red-400 mb-6">Virüs Uyarı Sayfası</h1>
    <div class="bg-red-900/20 border border-red-500/30 rounded-xl p-6">
      {{ format_virus_alert()|safe }}
    </div>
  </div>
</body>
</html>"""


QUARANTINE_HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FoxGuard - Karantina</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
body { font-family: 'Inter', sans-serif; }
</style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen">
  <nav class="bg-slate-900 border-b border-slate-700 sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="w-8 h-8 bg-amber-500 rounded-lg flex items-center justify-center text-white">🦊</div>
        <span class="font-bold text-lg text-amber-400">FoxGuard</span>
      </div>
      <div class="flex items-center gap-4">
        <span class="text-sm text-slate-400">{{ user }}</span>
        <a href="/" class="text-slate-400 hover:text-white">Geri</a>
        <a href="/logout" class="text-slate-400 hover:text-white">Çıkış</a>
      </div>
    </div>
  </nav>

  <div class="max-w-4xl mx-auto px-4 py-8">
    <h1 class="text-2xl font-bold mb-6">Karantina Listesi</h1>
    <div class="bg-slate-900 border border-slate-700 rounded-xl p-6 overflow-x-auto">
      <table class="w-full text-sm">
        <thead>
          <tr class="text-slate-400 border-b border-slate-700">
            <th class="pb-2 text-left">Dosya</th>
            <th class="pb-2 text-left">İşlem</th>
          </tr>
        </thead>
        <tbody>
          {% for item in items %}
          <tr class="border-b border-slate-800">
            <td class="py-2 text-slate-200">{{ item }}</td>
            <td class="py-2">
              <form method="POST" action="/quarantine/restore/{{ item }}" style="display:inline">
                <button type="submit" class="text-emerald-400 hover:text-emerald-300 text-sm">Geri Yükle</button>
              </form>
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% if not items %}
    <p class="text-slate-400 text-center py-8">Karantinada dosya yok.</p>
    {% endif %}
  </div>
</body>
</html>"""


PLUGINS_HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FoxGuard - Eklentiler</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
body { font-family: 'Inter', sans-serif; }
</style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen">
  <nav class="bg-slate-900 border-b border-slate-700 sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="w-8 h-8 bg-purple-500 rounded-lg flex items-center justify-center text-white">🦊</div>
        <span class="font-bold text-lg text-purple-400">FoxGuard</span>
      </div>
      <div class="flex items-center gap-4">
        <span class="text-sm text-slate-400">{{ user }}</span>
        <a href="/" class="text-slate-400 hover:text-white">Geri</a>
        <a href="/logout" class="text-slate-400 hover:text-white">Çıkış</a>
      </div>
    </div>
  </nav>

  <div class="max-w-4xl mx-auto px-4 py-8">
    <h1 class="text-2xl font-bold mb-6">Eklentiler</h1>
    <div class="bg-slate-900 border border-slate-700 rounded-xl p-6">
      <div class="flex justify-between items-center mb-4">
        <span class="text-slate-300 font-medium">Yüklü Eklentiler</span>
        <form method="POST" action="/plugins/reload" style="display:inline">
          <button type="submit" class="bg-slate-700 hover:bg-slate-600 text-white px-4 py-2 rounded text-sm transition">Yeniden Yükle</button>
        </form>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead>
            <tr class="text-slate-400 border-b border-slate-700">
              <th class="pb-2 text-left">Ad</th>
              <th class="pb-2 text-left">Durum</th>
              <th class="pb-2 text-left">Açıklama</th>
            </tr>
          </thead>
          <tbody>
            {% for name, info in plugins.items() %}
            <tr class="border-b border-slate-800 hover:bg-slate-800/50 transition">
              <td class="py-2 text-slate-200 font-medium">{{ name }}</td>
              <td class="py-2"><span class="px-2 py-0.5 bg-emerald-900/20 text-emerald-400 rounded text-xs">Aktif</span></td>
              <td class="py-2 text-slate-400">{{ info.get('description','') }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
  </div>
</body>
</html>"""


PROJECTS_HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FoxGuard - Projeler</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
body { font-family: 'Inter', sans-serif; }
</style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen">
  <nav class="bg-slate-900 border-b border-slate-700 sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="w-8 h-8 bg-blue-500 rounded-lg flex items-center justify-center text-white">🦊</div>
        <span class="font-bold text-lg text-blue-400">FoxGuard</span>
      </div>
      <div class="flex items-center gap-4">
        <span class="text-sm text-slate-400">{{ user }}</span>
        <a href="/" class="text-slate-400 hover:text-white">Geri</a>
        <a href="/logout" class="text-slate-400 hover:text-white">Çıkış</a>
      </div>
    </div>
  </nav>

  <div class="max-w-4xl mx-auto px-4 py-8">
    <h1 class="text-2xl font-bold mb-6">GitHub Proje İndirici</h1>
    <div class="bg-slate-900 border border-slate-700 rounded-xl p-6">
      <form method="POST" action="/projects/download" class="space-y-4">
        <div>
          <label class="block text-sm font-medium text-slate-300 mb-2">GitHub Repository URL</label>
          <input type="text" name="url" placeholder="https://github.com/owner/repo" required
            class="w-full bg-slate-800 border border-slate-600 rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-500">
        </div>
        <button type="submit" class="bg-blue-600 hover:bg-blue-500 text-white font-semibold py-3 rounded-lg transition shadow-lg">
          İndir ve Tara
        </button>
      </form>
    </div>
  </div>
</body>
</html>"""


EMBED_PAGE_HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FoxGuard Embed</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
body { font-family: 'Inter', sans-serif; }
</style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen p-4">
  <div class="max-w-2xl mx-auto">
    <h1 class="text-xl font-bold mb-4">FoxGuard Embed Widget</h1>
    <p class="text-slate-400 text-sm mb-6">Bu sayfayı iframe ile kendi web sitenize gömebilirsiniz.</p>
    <div id="embedContainer" class="bg-slate-900 border border-slate-700 rounded-xl p-6 min-h-[400px]">
      Embed içeriği burada görünür.
    </div>
    <script src="/static/embed.js"></script>
  </div>
</body>
</html>"""


if __name__ == "__main__":
    ensure_dirs()
    ensure_files()
    initialize_users()
    print(f"FoxGuard başlatılıyor: http://{HOST}:{PORT}")
    print("Sadece localhost erişimi açık. Dışarıya kapalı.")
    print(f"Eklentiler: {len(plugin_loader.plugins)} adet yüklü.")
    print(f"Kullanıcılar: {', '.join(AUTHORIZED_USERS.keys())}")
    print(f"AI Entegrasyonu: {'Aktif' if AI_CONFIG['enabled'] else 'Devre Dışı'} ({AI_CONFIG['model']})")
    app.run(host=HOST, port=PORT, debug=DEBUG)
