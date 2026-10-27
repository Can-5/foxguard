"""FoxGuard Embed Modülü.

Web sitelerine ve uygulamalara gömülebilir bir FoxGuard parçasıdır.
Sadece JavaScript snippet ve basit bir API istemcisi sunar.
"""

EMBED_JS = """
(function(){
  var FOXGUARD_URL = window.FOXGUARD_URL || 'http://127.0.0.1:8765';
  var container = document.createElement('div');
  container.id = 'foxguard-widget';
  container.style.position = 'fixed';
  container.style.bottom = '20px';
  container.style.right = '20px';
  container.style.zIndex = '9999';
  container.style.fontFamily = 'sans-serif';
  document.body.appendChild(container);

  function fetchStatus(){
    fetch(FOXGUARD_URL + '/api/embed/status', {credentials: 'include'})
      .then(function(r){ return r.json(); })
      .then(function(d){
        container.innerHTML =
          '<div style="background:#1e293b;color:#e2e8f0;padding:10px;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,0.3);max-width:260px;">' +
          '<div style="font-weight:bold;margin-bottom:6px;">🦊 FoxGuard</div>' +
          '<div style="font-size:12px;color:#4ade80;">Durum: ' + (d.status||'bilinmiyor') + '</div>' +
          '<div style="font-size:12px;color:#fbbf24;">Tehdit: ' + (d.threats||0) + '</div>' +
          '<button onclick="window.open(\'' + FOXGUARD_URL + '/scan/report\', \'_blank\')" style="margin-top:8px;padding:6px 10px;background:#38bdf8;border:none;border-radius:4px;cursor:pointer;color:#0f172a;">Rapor</button>' +
          '</div>';
      })
      .catch(function(){
        container.innerHTML = '<div style="color:#f87171;font-size:12px;">FoxGuard bağlantısı yok.</div>';
      });
  }

  fetchStatus();
  setInterval(fetchStatus, 60000);
})();
"""

EMBED_HTML_SNIPPET = """
<!-- FoxGuard Embed -->
<script>
  window.FOXGUARD_URL = 'http://127.0.0.1:8765';
</script>
<script src="{foxguard_url}/static/embed.js"></script>
"""


def get_embed_js() -> str:
    return EMBED_JS


def get_embed_html(foxguard_url: str = "http://127.0.0.1:8765") -> str:
    return EMBED_HTML_SNIPPET.format(foxguard_url=foxguard_url)


def save_embed_js(static_dir: str):
    """embed.js'yi statik klasöre kaydeder (web sunucusu için)."""
    os.makedirs(static_dir, exist_ok=True)
    with open(os.path.join(static_dir, "embed.js"), "w", encoding="utf-8") as f:
        f.write(EMBED_JS)

import os

if __name__ == "__main__":
    print(get_embed_html())
