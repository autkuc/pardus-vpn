// Package peer, sunucu tarafında bağlı istemcilerin (peer) durumunu takip eder.
package peer

import (
	"net"
	"sync"

	"pardus-vpn/internal/protocol"
)

// Peer, sunucunun tanıdığı tek bir istemciyi temsil eder.
type Peer struct {
	StaticPubKeyID string       // config eşleştirmesi için base64 kimlik
	AllowedIP      string       // bu peer'a tahsis edilmiş tünel IP'si (ör. "10.8.0.2")
	Address        *net.UDPAddr // son bilinen gerçek (dış) UDP adresi (roaming destekli)
	Session        *protocol.Session
	mu             sync.Mutex
}

// Table, sunucunun aktif oturumlarını iki şekilde indeksler:
// SessionID'ye göre (gelen veri paketlerini hızlıca eşlemek için) ve
// tünel IP'sine göre (TUN'dan gelen paketi doğru peer'a yönlendirmek için).
type Table struct {
	mu          sync.RWMutex
	bySessionID map[uint32]*Peer
	byTunnelIP  map[string]*Peer
}

// NewTable, boş bir peer tablosu oluşturur.
func NewTable() *Table {
	return &Table{
		bySessionID: make(map[uint32]*Peer),
		byTunnelIP:  make(map[string]*Peer),
	}
}

// Register, başarılı bir el sıkışma sonrası yeni (veya yenilenmiş) bir
// peer oturumunu tabloya ekler.
func (t *Table) Register(p *Peer) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.bySessionID[p.Session.SessionID] = p
	if p.AllowedIP != "" {
		t.byTunnelIP[p.AllowedIP] = p
	}
}

// BySessionID, verilen oturum kimliğine karşılık gelen peer'ı döndürür.
func (t *Table) BySessionID(id uint32) (*Peer, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	p, ok := t.bySessionID[id]
	return p, ok
}

// ByTunnelIP, tünel içi (VPN) IP adresine karşılık gelen peer'ı döndürür.
// TUN'dan okunan bir paketin hangi peer'a şifrelenip gönderileceğini
// belirlemek için kullanılır.
func (t *Table) ByTunnelIP(ip string) (*Peer, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	p, ok := t.byTunnelIP[ip]
	return p, ok
}

// UpdateAddress, roaming (NAT/IP değişikliği) durumunda peer'ın güncel
// UDP adresini kaydeder — WireGuard'daki gibi her geçerli paket bu adresi
// günceller.
func (p *Peer) UpdateAddress(addr *net.UDPAddr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Address = addr
}

// CurrentAddress, peer'a paket göndermek için kullanılacak son bilinen adresi döndürür.
func (p *Peer) CurrentAddress() *net.UDPAddr {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.Address
}
