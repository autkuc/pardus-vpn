// Pardus VPN Sunucusu.
//
// Kullanım:
//
//	sudo ./pardus-vpn-server -config /etc/pardus-vpn/server.conf
package main

import (
	"crypto/ecdh"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"pardus-vpn/internal/config"
	"pardus-vpn/internal/cryptox"
	"pardus-vpn/internal/peer"
	"pardus-vpn/internal/protocol"
	"pardus-vpn/internal/tuniface"
)

func main() {
	configPath := flag.String("config", "/etc/pardus-vpn/server.conf", "sunucu config dosyasının yolu")
	flag.Parse()

	if err := run(*configPath); err != nil {
		log.Fatalf("hata: %v", err)
	}
}

func run(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("config yüklenemedi: %w", err)
	}

	if cfg.Interface.PrivateKey == "" {
		return fmt.Errorf("config dosyasında [Interface] PrivateKey eksik")
	}
	serverPriv, err := cryptox.PrivateKeyFromBase64(cfg.Interface.PrivateKey)
	if err != nil {
		return fmt.Errorf("sunucu özel anahtarı okunamadı: %w", err)
	}
	serverStatic := &cryptox.KeyPair{Private: serverPriv, Public: serverPriv.PublicKey()}
	log.Printf("sunucu açık anahtarı: %s", serverStatic.PublicBase64())

	// İzinli peer listesini ve tünel IP eşleşmelerini config'ten kur.
	allowed := make(map[string]string) // PublicKeyID -> AllowedIP (tekil /32 varsayılır)
	for _, p := range cfg.Peers {
		if p.PublicKey == "" {
			return fmt.Errorf("[Peer] bölümünde PublicKey eksik")
		}
		pub, err := cryptox.PublicKeyFromBase64(p.PublicKey)
		if err != nil {
			return fmt.Errorf("peer açık anahtarı okunamadı: %w", err)
		}
		tunnelIP := ""
		if len(p.AllowedIPs) > 0 {
			tunnelIP = stripCIDR(p.AllowedIPs[0])
		}
		allowed[cryptox.PublicKeyID(pub)] = tunnelIP
		log.Printf("izinli peer eklendi: %s -> %s", cryptox.PublicKeyID(pub), tunnelIP)
	}

	isAllowed := func(pub *ecdh.PublicKey) bool {
		_, ok := allowed[cryptox.PublicKeyID(pub)]
		return ok
	}

	// TUN arayüzünü oluştur ve yapılandır.
	iface, err := tuniface.Create(cfg.Interface.DeviceName)
	if err != nil {
		return fmt.Errorf("TUN arayüzü oluşturulamadı: %w", err)
	}
	defer iface.Close()
	log.Printf("TUN arayüzü oluşturuldu: %s", iface.Name)

	if cfg.Interface.Address != "" {
		if err := tuniface.ConfigureAddress(iface.Name, cfg.Interface.Address); err != nil {
			return fmt.Errorf("arayüz adresi ayarlanamadı: %w", err)
		}
	}
	if err := tuniface.SetMTU(iface.Name, cfg.Interface.MTU); err != nil {
		log.Printf("uyarı: MTU ayarlanamadı: %v", err)
	}
	if err := tuniface.EnableIPv4Forwarding(); err != nil {
		log.Printf("uyarı: IP forwarding etkinleştirilemedi (manuel ayarlamanız gerekebilir): %v", err)
	}

	// UDP dinleme soketini aç.
	udpAddr := &net.UDPAddr{Port: cfg.Interface.ListenPort}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("UDP soketi açılamadı (port %d): %w", cfg.Interface.ListenPort, err)
	}
	defer conn.Close()
	log.Printf("UDP portu %d üzerinde dinleniyor", cfg.Interface.ListenPort)

	table := peer.NewTable()

	go tunToUDPLoop(iface, conn, table)
	udpToTUNLoop(conn, iface, table, serverStatic, isAllowed, allowed, cfg)

	return nil
}

// udpToTUNLoop, gelen UDP paketlerini işler: el sıkışma mesajlarını yönetir,
// veri paketlerini çözer ve TUN arayüzüne yazar.
func udpToTUNLoop(conn *net.UDPConn, iface *tuniface.Interface, table *peer.Table, serverStatic *cryptox.KeyPair, isAllowed func(*ecdh.PublicKey) bool, allowed map[string]string, cfg *config.Config) {
	buf := make([]byte, 65535)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("UDP okuma hatası: %v", err)
			continue
		}
		if n < 1 {
			continue
		}
		packet := buf[:n]

		switch packet[0] {
		case protocol.TypeHandshakeInit:
			respMsg, session, clientPub, err := protocol.ServerProcessHandshakeInit(packet, serverStatic, isAllowed)
			if err != nil {
				log.Printf("el sıkışma reddedildi (%s): %v", remoteAddr, err)
				continue
			}
			tunnelIP := allowed[cryptox.PublicKeyID(clientPub)]
			p := &peer.Peer{
				StaticPubKeyID: cryptox.PublicKeyID(clientPub),
				AllowedIP:      tunnelIP,
				Session:        session,
			}
			p.UpdateAddress(remoteAddr)
			table.Register(p)

			if _, err := conn.WriteToUDP(respMsg, remoteAddr); err != nil {
				log.Printf("el sıkışma yanıtı gönderilemedi: %v", err)
				continue
			}
			log.Printf("yeni peer bağlandı: %s (tünel IP: %s, oturum: %d)", remoteAddr, tunnelIP, session.SessionID)

		case protocol.TypeData, protocol.TypeKeepalive:
			if n < protocol.DataHeaderSize {
				continue
			}
			sessionID := binary.BigEndian.Uint32(packet[1:5])
			counter := binary.BigEndian.Uint64(packet[5:13])
			ciphertext := packet[13:]

			p, ok := table.BySessionID(sessionID)
			if !ok {
				log.Printf("bilinmeyen oturum kimliği, paket atlandı: %d", sessionID)
				continue
			}
			p.UpdateAddress(remoteAddr) // roaming desteği

			plaintext, err := p.Session.Decrypt(counter, ciphertext)
			if err != nil {
				log.Printf("paket çözülemedi (peer %s): %v", p.StaticPubKeyID, err)
				continue
			}
			if packet[0] == protocol.TypeKeepalive || len(plaintext) == 0 {
				continue // keepalive'ın TUN'a yazılacak bir yükü yok
			}
			if _, err := iface.Write(plaintext); err != nil {
				log.Printf("TUN'a yazılamadı: %v", err)
			}

		default:
			log.Printf("bilinmeyen paket tipi: %d (%s)", packet[0], remoteAddr)
		}
	}
}

// tunToUDPLoop, TUN arayüzünden okunan ham IP paketlerini hedef IP adresine
// göre doğru peer'a şifreleyip UDP üzerinden gönderir.
func tunToUDPLoop(iface *tuniface.Interface, conn *net.UDPConn, table *peer.Table) {
	buf := make([]byte, 65535)
	for {
		n, err := iface.Read(buf)
		if err != nil {
			log.Printf("TUN okuma hatası: %v", err)
			continue
		}
		if n < 20 {
			continue // geçerli bir IPv4 başlığı için minimum boyut
		}
		packet := buf[:n]

		destIP := net.IP(packet[16:20]).String() // IPv4 başlığında hedef adres offset 16
		p, ok := table.ByTunnelIP(destIP)
		if !ok {
			continue // bu hedefe giden bir peer/rota yok
		}

		counter, ciphertext := p.Session.Encrypt(packet)
		out := make([]byte, protocol.DataHeaderSize+len(ciphertext))
		out[0] = protocol.TypeData
		binary.BigEndian.PutUint32(out[1:5], p.Session.SessionID)
		binary.BigEndian.PutUint64(out[5:13], counter)
		copy(out[13:], ciphertext)

		addr := p.CurrentAddress()
		if addr == nil {
			continue
		}
		if _, err := conn.WriteToUDP(out, addr); err != nil {
			log.Printf("UDP'ye yazılamadı: %v", err)
		}
	}
}

// stripCIDR, "10.8.0.2/32" gibi bir CIDR'den yalnızca IP kısmını döndürür.
func stripCIDR(cidr string) string {
	for i := 0; i < len(cidr); i++ {
		if cidr[i] == '/' {
			return cidr[:i]
		}
	}
	return cidr
}

var _ = os.Stdout // (ileride log dosyası yönlendirmesi için ayrılmıştır)
