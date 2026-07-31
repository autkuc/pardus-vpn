package cryptox

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

// AEADSession, tek yönlü bir trafik akışı için türetilmiş anahtarla
// AES-256-GCM şifreleme/deşifreleme sağlar. Nonce, tekrar saldırılarını
// (replay) önlemek amacıyla artan bir sayaçtan (counter) üretilir.
type AEADSession struct {
	aead cipher.AEAD
}

// NewAEADSession, 32 baytlık bir anahtardan AES-256-GCM oturumu oluşturur.
func NewAEADSession(key []byte) (*AEADSession, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256 için 32 baytlık anahtar gerekli, %d bayt verildi", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes blok şifresi oluşturulamadı: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm modu oluşturulamadı: %w", err)
	}
	return &AEADSession{aead: aead}, nil
}

// nonceFromCounter, 12 baytlık GCM nonce'unu 8 baytlık sayaçtan üretir.
// İlk 4 bayt sıfırdır (gelecekte rastgele bir tuz için ayrılmıştır).
func nonceFromCounter(counter uint64) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}

// Seal, verilen sayaç değeriyle plaintext'i şifreler ve doğrulama etiketini ekler.
// AYNI SAYAÇ DEĞERİ AYNI ANAHTARLA ASLA İKİNCİ KEZ KULLANILMAMALIDIR.
func (s *AEADSession) Seal(counter uint64, plaintext []byte) []byte {
	nonce := nonceFromCounter(counter)
	return s.aead.Seal(nil, nonce, plaintext, nil)
}

// Open, şifreli metni doğrular ve çözer. Doğrulama başarısız olursa
// (paket değiştirilmiş, yanlış anahtar veya replay) hata döner.
func (s *AEADSession) Open(counter uint64, ciphertext []byte) ([]byte, error) {
	nonce := nonceFromCounter(counter)
	pt, err := s.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("paket doğrulanamadı (bozuk/sahte/yanlış anahtar): %w", err)
	}
	return pt, nil
}
