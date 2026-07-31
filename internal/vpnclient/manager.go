// Package vpnclient, VPN istemci bağlantı mantığını hem CLI (systemd
// servisi) hem de GUI (yerel web arayüzü) tarafından kullanılabilecek
// şekilde bir "Manager" olarak sarmalar. Bağlan/bağlantıyı kes komutları
// ve anlık durum (bağlı/bağlanıyor/hata, bayt sayaçları) buradan yönetilir.
package vpnclient

import (
	"context"
	"crypto/ecdh"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"pardus-vpn/internal/config"
	"pardus-vpn/internal/cryptox"
	"pardus-vpn/internal/protocol"
	"pardus-vpn/internal/tuniface"
)

// State, Manager'ın olabileceği durumları temsil eder.
type State string

const (
	StateDisconnected State = "disconnected"
	StateConnecting   State = "connecting"
	StateConnected    State = "connected"
	StateError        State = "error"
)

const keepaliveInterval = 20 * time.Second

// StatusInfo, GUI/CLI'ya sunulan anlık durum bilgisidir (JSON'a uygun).
type StatusInfo struct {
	State          State  `json:"state"`
	ServerEndpoint string `json:"server_endpoint,omitempty"`
	TunnelAddress  string `json:"tunnel_address,omitempty"`
	SessionID      uint32 `json:"session_id,omitempty"`
	ConnectedSince string `json:"connected_since,omitempty"`
	BytesSent      uint64 `json:"bytes_sent"`
	BytesRecv      uint64 `json:"bytes_recv"`
	LastError      string `json:"last_error,omitempty"`
}

// Manager, tek bir VPN bağlantısının yaşam döngüsünü yönetir.
type Manager struct {
	mu sync.Mutex

	configPath string
	cfg        *config.Config

	state       State
	lastError   string
	connectedAt time.Time

	conn    *net.UDPConn
	iface   *tuniface.Interface
	session *protocol.Session
	cancel  context.CancelFunc

	bytesSent atomic.Uint64
	bytesRecv atomic.Uint64
}

// NewManager, verilen config dosyasını kullanacak yeni bir Manager oluşturur.
func NewManager(configPath string) *Manager {
	return &Manager{configPath: configPath, state: StateDisconnected}
}

// Status, mevcut bağlantı durumunun anlık bir kopyasını döndürür.
func (m *Manager) Status() StatusInfo {
	m.mu.Lock()
	defer m.mu.Unlock()

	info := StatusInfo{
		State:     m.state,
		BytesSent: m.bytesSent.Load(),
		BytesRecv: m.bytesRecv.Load(),
		LastError: m.lastError,
	}
	if m.cfg != nil {
		info.TunnelAddress = m.cfg.Interface.Address
		if len(m.cfg.Peers) > 0 {
			info.ServerEndpoint = m.cfg.Peers[0].Endpoint
		}
	}
	if m.session != nil {
		info.SessionID = m.session.SessionID
	}
	if m.state == StateConnected {
		info.ConnectedSince = m.connectedAt.Format(time.RFC3339)
	}
	return info
}

// Connect, config dosyasını okur, sunucuyla el sıkışmayı gerçekleştirir,
// TUN arayüzünü açar ve arka plan döngülerini başlatır. Zaten bağlıyken
// tekrar çağrılırsa hata döner.
func (m *Manager) Connect() error {
	m.mu.Lock()
	if m.state == StateConnecting || m.state == StateConnected {
		m.mu.Unlock()
		return fmt.Errorf("zaten bağlı ya da bağlanma sürecinde")
	}
	m.state = StateConnecting
	m.lastError = ""
	m.mu.Unlock()

	cfg, err := config.Load(m.configPath)
	if err != nil {
		return m.fail(fmt.Errorf("config yüklenemedi: %w", err))
	}
	if len(cfg.Peers) == 0 {
		return m.fail(fmt.Errorf("config dosyasında en az bir [Peer] (sunucu) tanımlanmalı"))
	}
	serverPeerCfg := cfg.Peers[0]

	if cfg.Interface.PrivateKey == "" {
		return m.fail(fmt.Errorf("config dosyasında [Interface] PrivateKey eksik"))
	}
	clientPriv, err := cryptox.PrivateKeyFromBase64(cfg.Interface.PrivateKey)
	if err != nil {
		return m.fail(fmt.Errorf("istemci özel anahtarı okunamadı: %w", err))
	}
	clientStatic := &cryptox.KeyPair{Private: clientPriv, Public: clientPriv.PublicKey()}

	if serverPeerCfg.PublicKey == "" || serverPeerCfg.Endpoint == "" {
		return m.fail(fmt.Errorf("[Peer] bölümünde PublicKey ve Endpoint zorunludur"))
	}
	serverStaticPub, err := cryptox.PublicKeyFromBase64(serverPeerCfg.PublicKey)
	if err != nil {
		return m.fail(fmt.Errorf("sunucu açık anahtarı okunamadı: %w", err))
	}

	serverAddr, err := net.ResolveUDPAddr("udp", serverPeerCfg.Endpoint)
	if err != nil {
		return m.fail(fmt.Errorf("sunucu adresi çözümlenemedi (%s): %w", serverPeerCfg.Endpoint, err))
	}

	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		return m.fail(fmt.Errorf("UDP bağlantısı kurulamadı: %w", err))
	}

	session, err := performHandshake(conn, clientStatic, serverStaticPub)
	if err != nil {
		conn.Close()
		return m.fail(fmt.Errorf("el sıkışma başarısız: %w", err))
	}

	iface, err := tuniface.Create(cfg.Interface.DeviceName)
	if err != nil {
		conn.Close()
		return m.fail(fmt.Errorf("TUN arayüzü oluşturulamadı (root/CAP_NET_ADMIN gerekli): %w", err))
	}
	if cfg.Interface.Address != "" {
		if err := tuniface.ConfigureAddress(iface.Name, cfg.Interface.Address); err != nil {
			conn.Close()
			iface.Close()
			return m.fail(fmt.Errorf("arayüz adresi ayarlanamadı: %w", err))
		}
	}
	if err := tuniface.SetMTU(iface.Name, cfg.Interface.MTU); err != nil {
		log.Printf("uyarı: MTU ayarlanamadı: %v", err)
	}
	for _, cidr := range serverPeerCfg.AllowedIPs {
		if err := tuniface.AddRoute(cidr, iface.Name); err != nil {
			log.Printf("uyarı: rota eklenemedi (%s): %v", cidr, err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	m.mu.Lock()
	m.cfg = cfg
	m.conn = conn
	m.iface = iface
	m.session = session
	m.cancel = cancel
	m.state = StateConnected
	m.connectedAt = time.Now()
	m.bytesSent.Store(0)
	m.bytesRecv.Store(0)
	m.mu.Unlock()

	go m.keepaliveLoop(ctx, conn, session)
	go m.udpToTUNLoop(ctx, conn, iface, session)
	go m.tunToUDPLoop(ctx, iface, conn, session)

	return nil
}

// Disconnect, aktif bağlantıyı sonlandırır: arka plan döngülerini durdurur,
// soketi ve TUN arayüzünü kapatır.
func (m *Manager) Disconnect() error {
	m.mu.Lock()
	if m.state != StateConnected && m.state != StateConnecting {
		m.mu.Unlock()
		return fmt.Errorf("zaten bağlı değil")
	}
	cancel := m.cancel
	conn := m.conn
	iface := m.iface
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if conn != nil {
		conn.Close()
	}
	if iface != nil {
		iface.Close()
	}

	m.mu.Lock()
	m.state = StateDisconnected
	m.conn = nil
	m.iface = nil
	m.session = nil
	m.cancel = nil
	m.mu.Unlock()

	return nil
}

func (m *Manager) fail(err error) error {
	m.mu.Lock()
	m.state = StateError
	m.lastError = err.Error()
	m.mu.Unlock()
	log.Printf("hata: %v", err)
	return err
}

func performHandshake(conn *net.UDPConn, clientStatic *cryptox.KeyPair, serverStaticPub *ecdh.PublicKey) (*protocol.Session, error) {
	initMsg, ephemeral, sharedA, err := protocol.ClientHandshakeInit(clientStatic, serverStaticPub)
	if err != nil {
		return nil, fmt.Errorf("HandshakeInit oluşturulamadı: %w", err)
	}

	const maxAttempts = 5
	respBuf := make([]byte, protocol.HandshakeResponseSize)

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if _, err := conn.Write(initMsg); err != nil {
			return nil, fmt.Errorf("HandshakeInit gönderilemedi: %w", err)
		}
		if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			return nil, fmt.Errorf("okuma zaman aşımı ayarlanamadı: %w", err)
		}
		n, err := conn.Read(respBuf)
		if err != nil {
			log.Printf("el sıkışma yanıtı alınamadı (deneme %d/%d): %v", attempt, maxAttempts, err)
			continue
		}
		_ = conn.SetReadDeadline(time.Time{})

		session, err := protocol.ClientProcessHandshakeResponse(respBuf[:n], clientStatic, ephemeral, sharedA)
		if err != nil {
			return nil, fmt.Errorf("HandshakeResponse işlenemedi: %w", err)
		}
		return session, nil
	}

	return nil, fmt.Errorf("%d denemeden sonra sunucudan el sıkışma yanıtı alınamadı", maxAttempts)
}

func (m *Manager) keepaliveLoop(ctx context.Context, conn *net.UDPConn, session *protocol.Session) {
	ticker := time.NewTicker(keepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			counter, ciphertext := session.Encrypt(nil)
			out := make([]byte, protocol.DataHeaderSize+len(ciphertext))
			out[0] = protocol.TypeKeepalive
			binary.BigEndian.PutUint32(out[1:5], session.SessionID)
			binary.BigEndian.PutUint64(out[5:13], counter)
			copy(out[13:], ciphertext)
			if _, err := conn.Write(out); err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("keepalive gönderilemedi: %v", err)
			}
		}
	}
}

func (m *Manager) tunToUDPLoop(ctx context.Context, iface *tuniface.Interface, conn *net.UDPConn, session *protocol.Session) {
	buf := make([]byte, 65535)
	for {
		n, err := iface.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("TUN okuma hatası: %v", err)
			continue
		}
		packet := buf[:n]
		counter, ciphertext := session.Encrypt(packet)
		out := make([]byte, protocol.DataHeaderSize+len(ciphertext))
		out[0] = protocol.TypeData
		binary.BigEndian.PutUint32(out[1:5], session.SessionID)
		binary.BigEndian.PutUint64(out[5:13], counter)
		copy(out[13:], ciphertext)
		if _, err := conn.Write(out); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("UDP'ye yazılamadı: %v", err)
			continue
		}
		m.bytesSent.Add(uint64(n))
	}
}

func (m *Manager) udpToTUNLoop(ctx context.Context, conn *net.UDPConn, iface *tuniface.Interface, session *protocol.Session) {
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("UDP okuma hatası: %v", err)
			continue
		}
		if n < protocol.DataHeaderSize {
			continue
		}
		packet := buf[:n]
		if packet[0] != protocol.TypeData && packet[0] != protocol.TypeKeepalive {
			continue
		}
		counter := binary.BigEndian.Uint64(packet[5:13])
		ciphertext := packet[13:]
		plaintext, err := session.Decrypt(counter, ciphertext)
		if err != nil {
			log.Printf("paket çözülemedi: %v", err)
			continue
		}
		if len(plaintext) == 0 {
			continue
		}
		if _, err := iface.Write(plaintext); err != nil {
			log.Printf("TUN'a yazılamadı: %v", err)
			continue
		}
		m.bytesRecv.Add(uint64(len(plaintext)))
	}
}
