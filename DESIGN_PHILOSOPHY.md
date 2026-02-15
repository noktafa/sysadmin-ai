# SysAdmin AI — Tasarım Felsefesi

## Bu Araç Nedir

Durumsuz, CWD-takipli, sıralı komut yürütücüsü. Tanılama ve konfigürasyon aracı.
Otonom bir ajan değil. Arka plan işçisi değil. Uzun süren süreç yöneticisi değil.

## Temel İlke: Atomik Yürütme

Her komut `subprocess.run()` ile bağımsız bir süreçte çalışır. Önceki komutun alias'ı, değişkeni, shell fonksiyonu sonraki komutu etkilemez.

Bunun anlamı: LLM `ls` derse, `ls` çalışır. Üç dakika önce set edilen bir alias araya girmez.

**Sınır:** Alt süreç, üst Python sürecinin ortam değişkenlerini (`PATH`, `LANG`, `HTTP_PROXY`) miras alır. `env={}` verilmediği için tam izolasyon yok. Temiz bir shell'den temiz, ama steril değil.

## CWD Takibi

Shell, dizin bilgisini tutmaz. Araç tutar.

Her komutun sonuna bir sentinel (`__SYSADMIN_AI_PWD__`) ve `pwd` eklenir. Çıktı parse edilir, `shell_state["cwd"]` güncellenir. Sonraki komut bu dizinde başlatılır.

Neden önemli:
- Alt süreç çökerse dizin bilgisi kaybolmaz.
- `cd` komutu aracı bozmaz; sentinel mekanizması yeni dizini yakalar.
- Durum, shell'de değil Python'da yaşar. Kontrol bizdedir.

## Güvenlik: Üç Katmanlı Filtre

Docker "varsayılan güvenlik modeli" değil. Opt-in. Gerçek güvenlik modeli şu sırayla çalışır:

**Katman 1 — Bilişsel (soul.md):** Sistem promptu LLM'e "bunları yapma" der. İlk savunma hattı. LLM'in kendi kararıyla tehlikeli komut üretmemesi beklenir.

**Katman 2 — Statik (Regex):** `BLOCKED_PATTERNS` ve `GRAYLIST_PATTERNS` ile ~50 regex deseni. `rm -rf /`, `mkfs`, `dd`, reverse shell denemeleri burada yakalanır.

Bu katman hakkında önemli bir ayrım: Tehdit modeli, regex'i atlatmaya çalışan kötü niyetli bir insan değil. Tehdit, tanılama zincirinde `rm -rf /` hallüsinasyonu gören bir LLM. LLM'ler kendi çıktılarını obfuscate etmez. Regex, bu tehdit modeline yeterlidir.

**Katman 3 — Çalışma Zamanı (Docker, opsiyonel):** `--safe-mode` ile her şey tek kullanımlık bir konteyner içinde çalışır. Bilinmeyen bilinmeyenleri yakalar. Ama varsayılan değil çünkü kurulum karmaşıklığı getirir.

## 30 Saniyelik Duvar

`subprocess.run()` çağrısında `timeout=30`. Sabit kodlanmış. Yapılandırılabilir değil.

Bunun sonuçları:
- `apt upgrade`, büyük `tar` işlemleri, veritabanı dökümü yapılamaz.
- Araç, durum kontrolü (`ls`, `grep`, `systemctl status`) ve hafif düzenleme (`sed`, config yazma) için uygundur.
- Ağır işler insana kalır.
- Kullanıcı asla sonsuza kadar beklemez. Yanıt verebilirlik garanti edilir, kapasite pahasına.

Bu bir felsefe kararı değil. Makul bir ilk değer. İleride yapılandırılabilir hale getirilebilir.

## Sıralı (Turn-Based) Yürütme

Döngü: Kullanıcı konuşur → LLM komut üretir → komut çalışır → sonuç LLM'e döner → LLM karar verir → tekrar.

Eşzamanlı yürütme yok. "Arka planda logları takip ederken CPU kontrol et" yapılamaz.

Bu bir eksiklik değil, doğru tasarım kararı. Nedeni: LLM, N. komutun tam çıktısını görmeden N+1. komutu doğru seçemez. Mevcut modeller iç içe geçmiş kısmi çıktılarla iyi çalışamıyor. Sıralı yürütme, LLM yeteneklerinin şu anki durumuna uygun.

## Komut Öncelikli (Command-First)

Araç, LLM'e üç tool sunar: `run_shell_command`, `read_file`, `write_file`.

Python kodu çalıştırma aracı yok. LLM, sisteme kurulu olan standart ikili dosyaları (`ls`, `grep`, `systemctl`, `Get-Process`) kullanmak zorunda. Bu, aracın yönettiği sunucunun gerçekliğini yansıtır.

## Temiz Shell Avantajı

Bir komut sysadmin-ai'da çalışıyorsa, temiz bir shell'de çalışır. Bir komut başarısız oluyorsa, `.bashrc`'deki garip bir alias yüzünden değildir.

Bu, tanılama için güçlü bir özellik: "Benim makinemde çalışıyor çünkü garip bir alias'ım var" problemini ortadan kaldırır.

## Dürüst Bir Not

Bu belgedeki her kısıtlama bilinçli bir felsefe değil. Bazıları en basit çalışan çözüm:

- 30 saniyelik timeout: tek bir sabit kodlanmış tamsayı.
- Bloklayıcı döngü: mümkün olan en basit tool-call işleme.
- Ortam değişkeni mirası: `env={}` vermemek, `PATH`'e bağımlı komutları kırar.

Araç v0.12'de. Tasarım, ilkelerine ihanet etmeden büyüyebilir.
