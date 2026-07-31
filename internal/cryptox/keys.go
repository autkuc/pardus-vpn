package cryptox

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// KeyPair, bir X25519 (Curve25519 ECDH) özel/açık anahtar çiftini temsil eder.
type KeyPair struct {
	Private *ecdh.PrivateKey
	Public  *ecdh.PublicKey
}

// GenerateKeyPair, kriptografik olarak güvenli rastgelelik kaynağı kullanarak
// yeni bir X25519 anahtar çifti üretir.
func GenerateKeyPair() (*KeyPair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("anahtar çifti üretilemedi: %w", err)
	}
	return &KeyPair{Private: priv, Public: priv.PublicKey()}, nil
}

// PublicKeyFromBase64, base64 (standart) ile kodlanmış 32 baytlık bir X25519
// açık anahtarını çözer.
func PublicKeyFromBase64(s string) (*ecdh.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("açık anahtar base64 çözülemedi: %w", err)
	}
	pub, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("geçersiz X25519 açık anahtarı: %w", err)
	}
	return pub, nil
}

// PrivateKeyFromBase64, base64 (standart) ile kodlanmış 32 baytlık bir X25519
// özel anahtarını çözer.
func PrivateKeyFromBase64(s string) (*ecdh.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("özel anahtar base64 çözülemedi: %w", err)
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("geçersiz X25519 özel anahtarı: %w", err)
	}
	return priv, nil
}

// PublicBase64, açık anahtarı base64 (standart) olarak döndürür.
func (kp *KeyPair) PublicBase64() string {
	return base64.StdEncoding.EncodeToString(kp.Public.Bytes())
}

// PrivateBase64, özel anahtarı base64 (standart) olarak döndürür.
// UYARI: yalnızca yerel config dosyalarına yazmak için kullanılmalıdır.
func (kp *KeyPair) PrivateBase64() string {
	return base64.StdEncoding.EncodeToString(kp.Private.Bytes())
}

// PublicKeyFromBytes, ham (base64 olmayan) 32 baytlık bir X25519 açık
// anahtarından ecdh.PublicKey oluşturur. Tel üzerinden gelen anahtarları
// çözerken kullanılır.
func PublicKeyFromBytes(raw []byte) (*ecdh.PublicKey, error) {
	pub, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("geçersiz X25519 açık anahtarı (ham bayt): %w", err)
	}
	return pub, nil
}

// PublicKeyID, bir açık anahtarı peer eşleştirmesi için kullanılabilecek
// sabit uzunlukta bir string anahtara çevirir (map key olarak kullanılır).
func PublicKeyID(pub *ecdh.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub.Bytes())
}
