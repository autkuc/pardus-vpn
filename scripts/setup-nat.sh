#!/usr/bin/env bash
# Sunucunun VPN istemcilerine internet çıkışı (gateway) sağlaması için
# NAT/MASQUERADE kuralını ekler. İstemcilerin AllowedIPs = 0.0.0.0/0
# kullandığı "tam tünel" senaryosunda gereklidir.
#
# Kullanım: sudo ./scripts/setup-nat.sh <tun-arayuz-adi> <disa-cikan-arayuz>
# Örnek:    sudo ./scripts/setup-nat.sh pardus0 eth0

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Bu script root olarak çalıştırılmalıdır" >&2
  exit 1
fi

if [[ $# -ne 2 ]]; then
  echo "Kullanım: $0 <tun-arayuz-adi> <disa-cikan-arayuz>" >&2
  echo "Örnek:    $0 pardus0 eth0" >&2
  exit 1
fi

TUN_IF="$1"
WAN_IF="$2"

sysctl -w net.ipv4.ip_forward=1

iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE
iptables -A FORWARD -i "$TUN_IF" -o "$WAN_IF" -j ACCEPT
iptables -A FORWARD -i "$WAN_IF" -o "$TUN_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT

echo "NAT/MASQUERADE kuralları eklendi: $TUN_IF -> $WAN_IF"
echo "NOT: Bu kurallar kalıcı değildir. Kalıcı yapmak için netfilter-persistent"
echo "     veya iptables-save > /etc/iptables/rules.v4 kullanın."
