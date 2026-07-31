package tuniface

import (
	"fmt"
	"os/exec"
)

// runIP, "ip" komutunu verilen argümanlarla çalıştırır ve hata durumunda
// çıktıyı da içeren açıklayıcı bir hata döndürür.
func runIP(args ...string) error {
	cmd := exec.Command("ip", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("'ip %v' komutu başarısız: %w (çıktı: %s)", args, err, string(out))
	}
	return nil
}

// ConfigureAddress, arayüze bir CIDR adresi atar ve arayüzü etkinleştirir.
// Örnek cidr: "10.8.0.2/24"
func ConfigureAddress(ifaceName, cidr string) error {
	if err := runIP("addr", "add", cidr, "dev", ifaceName); err != nil {
		return err
	}
	return runIP("link", "set", "dev", ifaceName, "up")
}

// SetMTU, arayüzün MTU değerini ayarlar. UDP+şifreleme başlıkları için
// varsayılan 1420 civarı bir değer önerilir (WireGuard'ın kullandığına yakın).
func SetMTU(ifaceName string, mtu int) error {
	return runIP("link", "set", "dev", ifaceName, "mtu", fmt.Sprintf("%d", mtu))
}

// AddRoute, belirtilen CIDR hedefine giden trafiği bu arayüz üzerinden
// yönlendirir (istemci tarafında "0.0.0.0/0" ile tam tünelleme için kullanılır).
func AddRoute(destCIDR, ifaceName string) error {
	return runIP("route", "add", destCIDR, "dev", ifaceName)
}

// EnableIPv4Forwarding, sunucu tarafında paket yönlendirmeyi (IP forwarding)
// çekirdek seviyesinde etkinleştirir. NAT/gateway modunda çalışmak için gereklidir.
func EnableIPv4Forwarding() error {
	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip_forward etkinleştirilemedi: %w (çıktı: %s)", err, string(out))
	}
	return nil
}
