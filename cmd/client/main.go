// Pardus VPN İstemcisi (CLI/systemd modu).
//
// Kullanım:
//
//	sudo ./pardus-vpn-client -config /etc/pardus-vpn/client.conf
//
// Bu, doğrudan bağlanıp Ctrl+C'ye (veya systemd durdurmasına) kadar
// çalışan başsız (headless) moddur. Grafik arayüz için pardus-vpn-gui
// komutunu kullanın.
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"pardus-vpn/internal/vpnclient"
)

func main() {
	configPath := flag.String("config", "/etc/pardus-vpn/client.conf", "istemci config dosyasının yolu")
	flag.Parse()

	mgr := vpnclient.NewManager(*configPath)

	log.Printf("bağlanılıyor...")
	if err := mgr.Connect(); err != nil {
		log.Fatalf("bağlantı başarısız: %v", err)
	}

	status := mgr.Status()
	log.Printf("bağlandı (oturum: %d, sunucu: %s, tünel adresi: %s)", status.SessionID, status.ServerEndpoint, status.TunnelAddress)
	log.Printf("çıkmak için Ctrl+C")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Printf("bağlantı kapatılıyor...")
	if err := mgr.Disconnect(); err != nil {
		log.Printf("bağlantı kapatılırken hata: %v", err)
	}
}
