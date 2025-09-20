#!/bin/bash

# ==============================================================================
# Skrip untuk mengunduh, mengekstrak, dan menjalankan VLESS Manager
# Fitur: Membersihkan dirinya sendiri setelah selesai.
# ==============================================================================

# Hentikan eksekusi jika ada perintah yang gagal
set -e

# --- Variabel Konfigurasi ---
TARGET_DIR="/root/vless-manager"
FILE_URL="https://raw.githubusercontent.com/Elysya28/Script_installer_vps/main/vless-manager.zip"
ZIP_FILE_NAME="vless-manager.zip"
EXEC_SCRIPT="main.sh"

# --- Fungsi untuk menampilkan pesan ---
log() {
    echo "=> $1"
}

# --- Pengecekan Awal ---

# 1. Pastikan skrip dijalankan sebagai root
if [ "$(id -u)" -ne 0 ]; then
   echo "Kesalahan: Skrip ini harus dijalankan dengan hak akses root." >&2
   echo "Silakan coba lagi menggunakan: sudo bash $0" >&2
   exit 1
fi

# 2. Pastikan wget, unzip, dan tar terinstall
log "Memeriksa perangkat yang dibutuhkan (wget, unzip, tar)..."
if ! command -v wget &> /dev/null || ! command -v unzip &> /dev/null || ! command -v tar &> /dev/null; then
    log "wget/unzip/tar tidak ditemukan. Mencoba menginstall..."
    # Lakukan update hanya jika diperlukan untuk mempercepat
    apt-get update
    apt-get install -y wget unzip tar
fi

# --- Instalasi Speedtest CLI ---
log "Menginstall Speedtest CLI..."
# Unduh file, jika gagal tampilkan pesan error dan keluar
wget -q https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz || { echo "Kesalahan: Gagal mengunduh speedtest." >&2; exit 1; }
# Ekstrak file, sembunyikan output. Jika gagal, tampilkan error dan keluar
tar xzf ookla-speedtest-1.2.0-linux-x86_64.tgz > /dev/null 2>&1 || { echo "Kesalahan: Gagal mengekstrak speedtest." >&2; exit 1; }
# Pindahkan ke direktori bin agar bisa dipanggil secara global. Jika gagal, tampilkan error dan keluar
mv speedtest /usr/bin || { echo "Kesalahan: Gagal memindahkan speedtest ke /usr/bin (perlu akses root?)." >&2; exit 1; }
# Bersihkan file sisa instalasi
rm -f ookla-speedtest-1.2.0-linux-x86_64.tgz speedtest.* > /dev/null 2>&1
log "Speedtest CLI berhasil diinstall."

# --- Proses Utama ---

log "Membuat direktori instalasi di $TARGET_DIR"
mkdir -p "$TARGET_DIR"

# Pindah ke direktori target
cd "$TARGET_DIR"
log "Berpindah ke direktori $TARGET_DIR"

log "Mengunduh file dari GitHub..."
wget -q -O "$ZIP_FILE_NAME" "$FILE_URL"

log "Mengekstrak file arsip..."
# Opsi -o untuk menimpa file yang ada tanpa bertanya
unzip -o "$ZIP_FILE_NAME"

log "Membersihkan file arsip yang sudah tidak diperlukan..."
rm "$ZIP_FILE_NAME"

log "Memberikan izin eksekusi (755) ke semua file..."
chmod -R 755 .

log "Semua persiapan selesai. Menjalankan skrip utama ($EXEC_SCRIPT)..."
echo "------------------------------------------------------------"

# Menjalankan skrip utama
./"$EXEC_SCRIPT"

echo "------------------------------------------------------------"
log "Skrip utama telah selesai dieksekusi."

log "Membersihkan skrip installer ini (self-destruct)..."
(sleep 2 && rm -- "$0") &

exit 0
