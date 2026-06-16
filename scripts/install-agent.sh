#!/bin/bash
# scripts/install-agent.sh — Skrip instalasi otomatis untuk Nexus Agent di Linux
set -e

# Warna output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0;5m' # No Color

echo -e "${YELLOW}[*] Memulai instalasi Nexus Agent...${NC}"

# Pastikan dijalankan sebagai root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[Error] Skrip ini harus dijalankan sebagai root (sudo).${NC}"
  exit 1
fi

MANAGER_IP="127.0.0.1"
PORT_DATA="1514"
PORT_ENROLL="1515"

# Parsing argumen jika ada
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --manager-ip) MANAGER_IP="$2"; shift ;;
        --port-data) PORT_DATA="$2"; shift ;;
        --port-enroll) PORT_ENROLL="$2"; shift ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

echo -e "[*] Konfigurasi Manager IP: ${GREEN}$MANAGER_IP${NC}"
echo -e "[*] Konfigurasi Port Data: ${GREEN}$PORT_DATA${NC}"
echo -e "[*] Konfigurasi Port Enroll: ${GREEN}$PORT_ENROLL${NC}"

# 1. Membuat direktori konfigurasi & log
echo -e "[*] Membuat direktori sistem..."
mkdir -p /etc/nexus
mkdir -p /var/lib/nexus
mkdir -p /var/log/nexus

# 2. Menulis konfigurasi awal
cat <<EOF > /etc/nexus/agent.toml
# Konfigurasi Nexus Agent
manager_ip = "$MANAGER_IP"
port_data = $PORT_DATA
port_enroll = $PORT_ENROLL
agent_name = "$(hostname)"
EOF
echo -e "${GREEN}[OK] File konfigurasi dibuat di /etc/nexus/agent.toml${NC}"

# 3. Memindahkan / Menyalin binary (simulasi build atau copy)
# Jika dijalankan dari folder dev, salin binary hasil kompilasi
if [ -f "./target/release/nexus-agent" ]; then
    echo -e "[*] Menyalin binary release..."
    cp ./target/release/nexus-agent /usr/bin/nexus-agent
elif [ -f "./nexus-agent" ]; then
    echo -e "[*] Menyalin binary lokal..."
    cp ./nexus-agent /usr/bin/nexus-agent
else
    echo -e "${YELLOW}[!] Binary nexus-agent tidak ditemukan lokal. Menggunakan mock placeholder.${NC}"
    # Buat file executable tiruan jika binary belum dicompile untuk keperluan installer scaffolding
    cat <<EOF > /usr/bin/nexus-agent
#!/bin/bash
echo "[Nexus Agent Mock] Berjalan di latar belakang. Manager: $MANAGER_IP"
while true; do
    sleep 10
done
EOF
    chmod +x /usr/bin/nexus-agent
fi

# 4. Membuat systemd service file
echo -e "[*] Mendaftarkan systemd service..."
cat <<EOF > /etc/systemd/system/nexus-agent.service
[Unit]
Description=Nexus Security Agent Daemon
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/lib/nexus
ExecStart=/usr/bin/nexus-agent
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# 5. Reload daemon & Aktifkan Service
echo -e "[*] Menjalankan layanan daemon..."
systemctl daemon-reload
systemctl enable nexus-agent.service
systemctl restart nexus-agent.service

echo -e "${GREEN}[SUCCESS] Nexus Agent berhasil diinstal dan dijalankan!${NC}"
echo -e "[*] Periksa status layanan menggunakan: ${YELLOW}systemctl status nexus-agent${NC}"
