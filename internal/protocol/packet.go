// Package protocol, Pardus VPN'in tel (wire) formatını ve el sıkışma
// (handshake) mantığını içerir. Protokol, WireGuard'ın Noise_IK yaklaşımından
// ilham alan basitleştirilmiş bir tasarımdır: statik + geçici (ephemeral)
// X25519 anahtarları ile karşılıklı kimlik doğrulama ve ileri gizlilik
// (forward secrecy) sağlar.
//
// GÜVENLİK NOTU: Bu, eğitim/yarışma amaçlı basitleştirilmiş bir protokoldür.
// Üretim ortamında kullanılmadan önce bağımsız bir güvenlik incelemesinden
// geçirilmeli, tercihen tam Noise Protocol Framework (ör. Noise_IKpsk2)
// veya doğrudan WireGuard kullanılmalıdır.
package protocol

import "fmt"

// Paket tipleri (wire format'ın ilk baytı).
const (
	TypeHandshakeInit     byte = 1
	TypeHandshakeResponse byte = 2
	TypeData              byte = 3
	TypeKeepalive         byte = 4
)

const (
	PubKeySize    = 32 // X25519 açık anahtar boyutu
	TagSize       = 16 // AES-GCM doğrulama etiketi boyutu
	SessionIDSize = 4
	CounterSize   = 8

	// HandshakeInit: [type(1)][ClientEphemeralPub(32)][EncClientStaticPub(32+16)]
	HandshakeInitSize = 1 + PubKeySize + (PubKeySize + TagSize)

	// HandshakeResponse: [type(1)][ServerEphemeralPub(32)][SessionID(4)]
	HandshakeResponseSize = 1 + PubKeySize + SessionIDSize

	// Data/Keepalive header: [type(1)][SessionID(4)][Counter(8)]
	DataHeaderSize = 1 + SessionIDSize + CounterSize

	// Bir replay penceresinde kabul edilen maksimum geri kayma.
	ReplayWindowSize = 1024
)

// ReplayGuard, kayan pencere (sliding window) tekniğiyle tekrar saldırısı
// (replay attack) tespiti yapar. WireGuard'ın kullandığı yaklaşıma benzer.
type ReplayGuard struct {
	highest uint64
	window  uint64 // bitmask: highest'e göre son ReplayWindowSize bitin durumu
}

// Check, bir sayaç değerinin daha önce görülüp görülmediğini kontrol eder
// ve görülmemişse pencereyi günceller. Geçerliyse nil, replay ise hata döner.
func (r *ReplayGuard) Check(counter uint64) error {
	if counter == 0 && r.highest == 0 && r.window == 0 {
		// İlk paket (sayaç 0'dan başlar).
		r.window = 1
		return nil
	}

	if counter > r.highest {
		shift := counter - r.highest
		if shift >= ReplayWindowSize {
			r.window = 1
		} else {
			r.window <<= shift
			r.window |= 1
		}
		r.highest = counter
		return nil
	}

	diff := r.highest - counter
	if diff >= ReplayWindowSize {
		return fmt.Errorf("paket çok eski, pencere dışında (counter=%d, highest=%d)", counter, r.highest)
	}

	bit := uint64(1) << diff
	if r.window&bit != 0 {
		return fmt.Errorf("tekrar saldırısı tespit edildi (replay), counter=%d zaten görülmüş", counter)
	}
	r.window |= bit
	return nil
}
