#!/usr/bin/env bash
# Pardus VPN - Kurulum Scripti
# Derlenmiş binary'leri /usr/local/bin altına, config'leri /etc/pardus-vpn
# altına, systemd servis dosyalarını /etc/systemd/system altına kurar.
#
# Kullanım: sudo ./scripts/install.sh

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Bu script root olarak çalıştırılmalıdır (sudo ./scripts/install.sh)" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Go binary'leri derleniyor..."
cd "$ROOT_DIR"
go build -o /tmp/pardus-vpn-server ./cmd/server
go build -o /tmp/pardus-vpn-client ./cmd/client
go build -o /tmp/pardus-vpn-genkey ./cmd/genkey
go build -o /tmp/pardus-vpn-gui ./cmd/gui

echo "==> Binary'ler /usr/local/bin altına kopyalanıyor..."
install -m 0755 /tmp/pardus-vpn-server /usr/local/bin/pardus-vpn-server
install -m 0755 /tmp/pardus-vpn-client /usr/local/bin/pardus-vpn-client
install -m 0755 /tmp/pardus-vpn-genkey /usr/local/bin/pardus-vpn-genkey
install -m 0755 /tmp/pardus-vpn-gui /usr/local/bin/pardus-vpn-gui

echo "==> Config dizini oluşturuluyor: /etc/pardus-vpn"
mkdir -p /etc/pardus-vpn
if [[ ! -f /etc/pardus-vpn/server.conf ]]; then
  cp "$ROOT_DIR/configs/server.conf.example" /etc/pardus-vpn/server.conf
  echo "    /etc/pardus-vpn/server.conf oluşturuldu (örnek değerlerle, DÜZENLEYİN)"
fi
if [[ ! -f /etc/pardus-vpn/client.conf ]]; then
  cp "$ROOT_DIR/configs/client.conf.example" /etc/pardus-vpn/client.conf
  echo "    /etc/pardus-vpn/client.conf oluşturuldu (örnek değerlerle, DÜZENLEYİN)"
fi
chmod 600 /etc/pardus-vpn/*.conf

echo "==> systemd servis dosyaları kopyalanıyor..."
cp "$ROOT_DIR/systemd/pardus-vpn-server.service" /etc/systemd/system/
cp "$ROOT_DIR/systemd/pardus-vpn-client.service" /etc/systemd/system/
systemctl daemon-reload

if [[ -d /usr/share/applications ]]; then
  echo "==> Masaüstü kısayolu ekleniyor (Uygulamalar menüsü)..."
  cp "$ROOT_DIR/desktop/pardus-vpn-gui.desktop" /usr/share/applications/
fi

cat <<'EOF'

Kurulum tamamlandı.

Sonraki adımlar:
  1. Anahtar üretin:          pardus-vpn-genkey
  2. /etc/pardus-vpn/server.conf ve client.conf dosyalarını düzenleyin
  3. Sunucuda başlatın:       sudo systemctl enable --now pardus-vpn-server
  4. İstemcide (CLI ile) başlatın:  sudo systemctl enable --now pardus-vpn-client
     --- VEYA arayüz ile ---
     sudo pardus-vpn-gui -config /etc/pardus-vpn/client.conf
     ardından tarayıcıda http://127.0.0.1:7777 açın
  5. Durumu kontrol edin:     sudo systemctl status pardus-vpn-server
  6. Logları izleyin:         sudo journalctl -u pardus-vpn-server -f

EOF
