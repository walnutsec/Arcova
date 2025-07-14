# Arcova Protocol

**Arcova** adalah sebuah tool *command-line* yang powerful dan serbaguna, dirancang untuk kebutuhan enkripsi modern dan steganografi. Dibangun dengan Python untuk kemudahan penggunaan dan C++ untuk performa tinggi pada tugas-tugas intensif.

---

## ✨ Fitur Utama

* **Enkripsi & Dekripsi File/Teks:** Mengamankan data menggunakan kombinasi standar industri AES-256 (GCM) untuk data dan RSA-4096 untuk membungkus kunci (key wrapping).
* **Manajemen Kunci:** Generate dan kelola pasangan kunci RSA untuk enkripsi asimetris.
* **Steganografi F5:** Sembunyikan file rahasia di dalam gambar JPEG menggunakan algoritma F5 yang efisien, dengan lapisan enkripsi tambahan untuk keamanan ganda.
* **Keamanan Password:** Menggunakan Argon2, algoritma hashing modern, untuk mengamankan password dan master key.
* **User-Friendly CLI:** Antarmuka baris perintah (CLI) yang interaktif dan mudah digunakan.

## 🛠️ Tumpukan Teknologi

* **Bahasa Utama:** Python
* **Modul Kinerja Tinggi:** C++
* **Jembatan Python/C++:** pybind11
* **Library Kriptografi:** PyCryptodome (AES, RSA), PyNaCl, Argon2
* **Library Lainnya:** Reed-Solomon, TQDM

---

## 🚀 Instalasi

Ada dua cara untuk menginstall Arcova, tergantung kebutuhan Anda.

### 1. Cara Mudah (Untuk Pengguna Biasa)

Cara ini direkomendasikan jika Anda hanya ingin menggunakan aplikasi tanpa perlu meng-compile dari source code.

1.  **Download Rilis Terbaru:**
    * Pergi ke halaman **[Releases](https://github.com/walnutsec/Arcova/releases)** di repository ini.
    * Download file yang berakhiran `.whl` yang sesuai dengan sistem operasi Anda (misalnya, `...-linux_x86_64.whl` untuk Linux).

2.  **Install dengan `pip`:**
    * Buka terminal di folder tempat Anda men-download file `.whl`.
    * Jalankan perintah berikut (ganti nama file sesuai dengan yang Anda download):
        ```bash
        pip install arcova-1.0.0-cp312-cp312-linux_x86_64.whl
        ```

### 2. Cara Developer (Membangun dari Source Code)

Cara ini untuk developer yang ingin meng-compile sendiri atau berkontribusi pada proyek.

1.  **Clone Repository:**
    ```bash
    git clone [https://github.com/walnutsec/Arcova.git](https://github.com/walnutsec/Arcova.git)
    cd Arcova
    ```

2.  **Pastikan Dependensi Build Terinstall:**
    * **Untuk Linux (Debian/Ubuntu/Mint):**
        ```bash
        sudo apt update
        sudo apt install build-essential python3-dev python3-venv libjpeg-dev libssl-dev
        ```

3.  **Setup Lingkungan Virtual & Build:**
    ```bash
    # Buat dan aktifkan virtual environment
    python3 -m venv venv
    source venv/bin/activate

    # Install build tools
    pip install build

    # Build paketnya
    python -m build
    ```

4.  **Install Paket yang Sudah di-Build:**
    ```bash
    pip install dist/nama_file_arcova.whl
    ```

---

## 💻 Cara Penggunaan

Setelah instalasi berhasil (lewat cara manapun), cukup buka terminal dan jalankan perintah:

```bash
arcova
