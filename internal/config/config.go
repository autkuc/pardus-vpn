// Package config, WireGuard'ın .conf formatına benzer basit bir INI tarzı
// yapılandırma dosyasını okur. [Interface] tek bir bölüm, [Peer] ise
// tekrarlanabilen bir bölümdür (sunucuda birden çok istemci tanımlamak için).
package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// InterfaceSection, [Interface] bölümündeki alanları temsil eder.
type InterfaceSection struct {
	PrivateKey string // base64 X25519 özel anahtarı
	Address    string // ör. "10.8.0.1/24"
	ListenPort int    // sadece sunucu için anlamlıdır
	DeviceName string // TUN aygıt adı, ör. "pardus0"
	MTU        int
}

// PeerSection, bir [Peer] bölümündeki alanları temsil eder.
type PeerSection struct {
	PublicKey  string   // base64 X25519 açık anahtarı
	Endpoint   string   // "host:port" (istemci config'inde sunucu adresi)
	AllowedIPs []string // CIDR listesi
}

// Config, ayrıştırılmış tüm dosyayı temsil eder.
type Config struct {
	Interface InterfaceSection
	Peers     []PeerSection
}

// Load, verilen yoldaki config dosyasını okur ve ayrıştırır.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config dosyası açılamadı (%s): %w", path, err)
	}
	defer f.Close()

	cfg := &Config{}
	var currentSection string
	var currentPeer *PeerSection

	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section := strings.TrimSpace(strings.Trim(line, "[]"))
			switch strings.ToLower(section) {
			case "interface":
				currentSection = "interface"
				currentPeer = nil
			case "peer":
				currentSection = "peer"
				cfg.Peers = append(cfg.Peers, PeerSection{})
				currentPeer = &cfg.Peers[len(cfg.Peers)-1]
			default:
				return nil, fmt.Errorf("%s:%d: bilinmeyen bölüm [%s]", path, lineNo, section)
			}
			continue
		}

		key, value, err := splitKeyValue(line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}

		switch currentSection {
		case "interface":
			if err := applyInterfaceField(&cfg.Interface, key, value); err != nil {
				return nil, fmt.Errorf("%s:%d: %w", path, lineNo, err)
			}
		case "peer":
			if currentPeer == nil {
				return nil, fmt.Errorf("%s:%d: [Peer] bölümü dışında peer alanı: %s", path, lineNo, key)
			}
			if err := applyPeerField(currentPeer, key, value); err != nil {
				return nil, fmt.Errorf("%s:%d: %w", path, lineNo, err)
			}
		default:
			return nil, fmt.Errorf("%s:%d: bölüm başlığından önce alan tanımlanamaz: %s", path, lineNo, key)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("config dosyası okunurken hata: %w", err)
	}

	if cfg.Interface.MTU == 0 {
		cfg.Interface.MTU = 1420 // WireGuard'ın kullandığına yakın güvenli varsayılan
	}
	if cfg.Interface.DeviceName == "" {
		cfg.Interface.DeviceName = "pardus0"
	}

	return cfg, nil
}

func splitKeyValue(line string) (key, value string, err error) {
	idx := strings.Index(line, "=")
	if idx < 0 {
		return "", "", fmt.Errorf("geçersiz satır (anahtar=değer bekleniyordu): %q", line)
	}
	key = strings.TrimSpace(line[:idx])
	value = strings.TrimSpace(line[idx+1:])
	return key, value, nil
}

func applyInterfaceField(sec *InterfaceSection, key, value string) error {
	switch strings.ToLower(key) {
	case "privatekey":
		sec.PrivateKey = value
	case "address":
		sec.Address = value
	case "listenport":
		port, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("geçersiz ListenPort değeri %q: %w", value, err)
		}
		sec.ListenPort = port
	case "devicename":
		sec.DeviceName = value
	case "mtu":
		mtu, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("geçersiz MTU değeri %q: %w", value, err)
		}
		sec.MTU = mtu
	default:
		return fmt.Errorf("[Interface] bölümünde bilinmeyen alan: %s", key)
	}
	return nil
}

func applyPeerField(sec *PeerSection, key, value string) error {
	switch strings.ToLower(key) {
	case "publickey":
		sec.PublicKey = value
	case "endpoint":
		sec.Endpoint = value
	case "allowedips", "allowedip":
		parts := strings.Split(value, ",")
		for _, p := range parts {
			sec.AllowedIPs = append(sec.AllowedIPs, strings.TrimSpace(p))
		}
	default:
		return fmt.Errorf("[Peer] bölümünde bilinmeyen alan: %s", key)
	}
	return nil
}
