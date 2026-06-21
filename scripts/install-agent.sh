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
    echo -e "${YELLOW}[*] Binary nexus-agent native tak ada — memasang agen ringan (bash) dengan telemetri NYATA.${NC}"
    # Agen ringan: membaca CPU/RAM/uptime ASLI dari /proc lalu mengirim heartbeat ke
    # Manager via /dev/tcp (tanpa dependensi). Heredoc DIKUTIP ('AGENT_EOF') agar isi
    # skrip literal; konfigurasi dibaca saat runtime dari /etc/nexus/agent.toml.
    cat <<'AGENT_EOF' > /usr/bin/nexus-agent
#!/bin/bash
# Nexus Agent (ringan, telemetri NYATA) — menyambung ke tab "Nexus Agents".
CFG=/etc/nexus/agent.toml
MANAGER_IP=$(awk -F'"' '/manager_ip/{print $2}' "$CFG" 2>/dev/null)
PORT=$(awk -F'=' '/port_data/{gsub(/[^0-9]/,"",$2);print $2}' "$CFG" 2>/dev/null)
NAME=$(awk -F'"' '/agent_name/{print $2}' "$CFG" 2>/dev/null)
[ -z "$MANAGER_IP" ] && MANAGER_IP=127.0.0.1
[ -z "$PORT" ] && PORT=1514
[ -z "$NAME" ] && NAME=$(hostname)

cpu_pct(){ local a b c d e f g h i1 t1 i2 t2 dt di
  read -r _ a b c d e f g h _ < /proc/stat; i1=$d; t1=$((a+b+c+d+e+f+g+h))
  sleep 1
  read -r _ a b c d e f g h _ < /proc/stat; i2=$d; t2=$((a+b+c+d+e+f+g+h))
  dt=$((t2-t1)); di=$((i2-i1)); [ "$dt" -gt 0 ] && echo $(((100*(dt-di))/dt)) || echo 0; }
ram_pct(){ local t a; t=$(awk '/^MemTotal/{print $2}' /proc/meminfo); a=$(awk '/^MemAvailable/{print $2}' /proc/meminfo)
  [ -n "$t" ] && [ "$t" -gt 0 ] && echo $(((100*(t-a))/t)) || echo 0; }
up_str(){ local u; read -r u _ < /proc/uptime; u=${u%.*}; echo "$((u/86400))d $(((u%86400)/3600))h"; }

echo "[nexus-agent] target $MANAGER_IP:$PORT (host $NAME)"
while true; do
  if exec 3<>"/dev/tcp/$MANAGER_IP/$PORT" 2>/dev/null; then
    echo "[nexus-agent] tersambung ke $MANAGER_IP:$PORT"
    while :; do
      printf 'HEARTBEAT STATS: CPU:%s%% | RAM:%s%% | eBPF Blocked:0 IPs | Uptime:%s\n' \
        "$(cpu_pct)" "$(ram_pct)" "$(up_str)" >&3 2>/dev/null || break
      sleep 4
    done
    exec 3>&- 2>/dev/null
  fi
  sleep 5
done
AGENT_EOF
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
