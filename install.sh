#!/bin/bash

# ==============================================================================
# Skrip untuk mengunduh, mengekstrak, dan menjalankan Trojan Manager
# Fitur: Membersihkan dirinya sendiri setelah selesai.
# ==============================================================================

# Hentikan eksekusi jika ada perintah yang gagal
set -e

# --- Variabel Konfigurasi ---
TARGET_DIR="/root/trojan-manager"
FILE_URL="https://raw.githubusercontent.com/Elysya28/trojan-vps/main/trojan-manager.zip"
ZIP_FILE_NAME="trojan-manager.zip"
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

# 2. Pastikan wget dan unzip terinstall
log "Memeriksa perangkat yang dibutuhkan (wget dan unzip)..."
if ! command -v wget &> /dev/null || ! command -v unzip &> /dev/null; then
    log "wget atau unzip tidak ditemukan. Mencoba menginstall..."
    apt-get update
    apt-get install -y wget unzip
fi

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
