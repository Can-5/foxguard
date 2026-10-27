# FoxGuard — Gelişmiş Güvenlik ve Saldırı Engelleme Yazılımı

FoxGuard, FoxAI Browser ve sisteminiz için geliştirilmiş, **sadece siz ve benim (asistan) erişebileceğimiz** bir güvenlik yazılımıdır.

## Özellikler

- **Kimlik doğrulama**: Sadece iki yetkili kullanıcı (`ilkaycan`, `assistant`) giriş yapabilir. Şifreler SHA-256 ile saklanır.
- **Saldırı engelleme**: XSS, SQL injection, komut enjeksiyonu, path traversal gibi saldırı kalıpları tespit edilip engellenir.
- **Virüs / zararlı yazılım taraması**: Dosya adı ve içerik tabanlı imza taraması yapılır.
- **Tarayıcı raporu**: Tarama sonuçları tarayıcıda HTML olarak görüntülenir.
- **Tehdit işlemleri**: Tespit edilen her tehdit için kullanıcıya **Sil** / **Karantina** / **Yükle (Riskli)** seçeneği sunulur.
- **Karantina**: Zararlı dosyalar karantinaya alınır, istenirse geri yüklenebilir.
- **Yerel only**: Sunucu sadece `127.0.0.1` üzerinden çalışır. Dış ağ erişimi yok.

## Kurulum

```bash
cd foxguard
pip install -r requirements.txt
python app.py
```

Tarayıcıdan: http://127.0.0.1:8765

İlk giriş şifreleri:
- `ilkaycan` / `ilkaycanFoxGuard2026!`
- `assistant` / `assistantFoxGuard2026!`

İlk girişten sonra şifreleri değiştirmeniz önerilir.

## Erişim Kısıtlaması

FoxGuard sadece localhost'tan erişilebilir. Başka bir makine veya dış ağdan erişim engellenmiştir. Sadece siz ve ben bu arayüzü görebilir ve işlem yapabiliriz.

## Virüs Tespit Akışı

1. Tarama çalıştırılır.
2. Zararlı dosya tespit edilir.
3. Tarayıcıda "Virüs / Zararlı Yazılım Tespit Edildi" uyarı sayfası açılır.
4. Kullanıcı şunlardan birini seçer:
   - **Sil**: Dosya kalıcı olarak silinir.
   - **Karantina**: Dosya karantinaya alınır (geriye dönüş mümkün).
   - **Yükle (Riskli)**: Kullanıcı riski kabul eder, dosya olduğu gibi bırakılır.

## Klasör Yapısı

```
foxguard/
├── app.py           # Flask web arayüzü
├── auth.py          # Kimlik doğrulama
├── scanner.py       # Tarama motoru
├── blocker.py       # Saldırı engelleyici
├── reporter.py      # HTML rapor
├── config.py        # Yapılandırma
├── requirements.txt
├── README.md
├── data/
│   ├── users.json
│   ├── signatures.db
│   └── quarantine/
└── logs/
    └── foxguard.log
```

## Güvenlik Notu

Bu yazılım, eğitim ve temel koruma amacıyla hazırlanmıştır. Üretim ortamında kullanmadan önce şifre anahtarı (`FOXGUARD_SECRET`) ve şifreleri değiştirmeniz, ayrıca güçlü bir kimlik doğrulama yöntemi eklemeniz önerilir.
