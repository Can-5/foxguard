"""FoxGuard tarayıcı raporu oluşturma modülü."""

from datetime import datetime


def format_scan_report(scan_result: dict) -> str:
    """Tarama sonucunu HTML rapor olarak biçimlendirir."""
    lines = []
    lines.append("<!DOCTYPE html>")
    lines.append("<html lang='tr'><head><meta charset='UTF-8'>")
    lines.append("<title>FoxGuard Tarama Raporu</title>")
    lines.append("<style>")
    lines.append("body{font-family:sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem;}")
    lines.append(".card{background:#1e293b;border-radius:12px;padding:1.5rem;margin-bottom:1rem;box-shadow:0 4px 6px -1px rgba(0,0,0,0.3);}")
    lines.append(".clean{color:#4ade80;}.threat{color:#f87171;}.warn{color:#fbbf24;}")
    lines.append("table{width:100%;border-collapse:collapse;margin-top:1rem;}")
    lines.append("th,td{border:1px solid #334155;padding:0.5rem;text-align:left;}")
    lines.append("th{background:#334155;}")
    lines.append(".btn{padding:0.4rem 0.8rem;border:none;border-radius:6px;cursor:pointer;margin-right:0.5rem;}")
    lines.append(".btn-del{background:#ef4444;color:#fff;}.btn-ins{background:#22c55e;color:#fff;}.btn-q{background:#f59e0b;color:#fff;}")
    lines.append("</style></head><body>")
    lines.append("<h1>🦊 FoxGuard Tarama Raporu</h1>")
    lines.append(f"<p><strong>Tarih:</strong> {scan_result.get('scanned_at','')}</p>")
    lines.append(f"<p><strong>Toplam dosya:</strong> {scan_result.get('total_files',0)}</p>")
    lines.append(f"<p><strong>Toplam tehdit:</strong> <span class='{'clean' if scan_result.get('total_threats',0)==0 else 'threat'}'>{scan_result.get('total_threats',0)}</span></p>")
    lines.append(f"<p><strong>Durum:</strong> <span class='{'clean' if scan_result.get('status')=='clean' else 'threat'}'>{scan_result.get('status','')}</span></p>")

    for pr in scan_result.get("paths", []):
        lines.append("<div class='card'>")
        lines.append(f"<h3>📁 {pr['path']}</h3>")
        lines.append(f"<p>Taranan dosya: {pr['files_scanned']}</p>")
        if pr.get("threats"):
            lines.append("<table><tr><th>Dosya</th><th>Tür</th><th>Şiddet</th><th>Detay</th><th>İşlem</th></tr>")
            for t in pr["threats"]:
                fid = t["file"].replace("/", "_").replace(":", "_")
                lines.append("<tr>")
                lines.append(f"<td>{t['file']}</td>")
                lines.append(f"<td class='{'clean' if t['type']=='malware_signature' else 'warn'}'>{t['type']}</td>")
                lines.append(f"<td class='threat'>{t['severity']}</td>")
                lines.append(f"<td>{t['detail']}</td>")
                lines.append(f"<td>")
                lines.append(f"<button class='btn btn-del' onclick=\"action('delete','{fid}')\">Sil</button>")
                lines.append(f"<button class='btn btn-q' onclick=\"action('quarantine','{fid}')\">Karantina</button>")
                lines.append(f"<button class='btn btn-ins' onclick=\"action('install','{fid}')\">Yükle (Riskli)</button>")
                lines.append("</td>")
                lines.append("</tr>")
            lines.append("</table>")
        else:
            lines.append("<p class='clean'>✓ Tehdit bulunamadı.</p>")
        lines.append("</div>")

    lines.append("<script>")
    lines.append("function action(type,id){fetch('/api/action',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type:type,id:id}}).then(r=>r.json()).then(d=>{alert(d.message);location.reload();});}")
    lines.append("</script>")
    lines.append("</body></html>")
    return "\n".join(lines)


def format_virus_alert(virus_name: str, file_path: str) -> str:
    """Virüs uyarı sayfası."""
    return f"""<!DOCTYPE html>
<html lang='tr'><head><meta charset='UTF-8'><title>FoxGuard - Virüs Tespit Edildi</title>
<style>
body{{font-family:sans-serif;background:#1e1b4b;color:#fff;padding:2rem;text-align:center;}}
.card{{background:#4c1d95;border-radius:16px;padding:2rem;max-width:500px;margin:0 auto;box-shadow:0 20px 25px -5px rgba(0,0,0,0.5);}}
.big{{font-size:3rem;margin-bottom:1rem;}}
.btn{{padding:1rem 2rem;border:none;border-radius:8px;font-size:1rem;cursor:pointer;margin:0.5rem;}}
.del{{background:#dc2626;color:#fff;}}
.ins{{background:#16a34a;color:#fff;}}
.q{{background:#d97706;color:#fff;}}
</style></head><body>
<div class='card'>
<div class='big'>⚠️</div>
<h2>Virüs / Zararlı Yazılım Tespit Edildi</h2>
<p><strong>İsim:</strong> {virus_name}</p>
<p><strong>Dosya:</strong> {file_path}</p>
<p>FoxGuard bu dosyayı zararlı olarak işaretledi. Yapmak istediğiniz işlemi seçin:</p>
<button class='btn del' onclick="location.href='/api/virus/delete?file={file_path}'">🗑️ Sil</button>
<button class='btn q' onclick="location.href='/api/virus/quarantine?file={file_path}'">🦠 Karantina</button>
<button class='btn ins' onclick="location.href='/api/virus/install?file={file_path}'">⚠️ Yine de Yükle</button>
</div></body></html>"""
