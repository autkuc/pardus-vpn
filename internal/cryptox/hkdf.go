// Package cryptox, Pardus VPN için gerekli kriptografik ilkelleri sağlar.
// Sadece Go standart kütüphanesi kullanılır (harici bağımlılık yoktur),
// bu sayede derleme ve dağıtım basitleşir.
package cryptox

import (
	"crypto/hmac"
	"crypto/sha256"
)

// hkdfExtract, RFC 5869'daki HKDF-Extract adımını uygular.
func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// hkdfExpand, RFC 5869'daki HKDF-Expand adımını uygular.
func hkdfExpand(prk, info []byte, length int) []byte {
	var (
		t   []byte
		okm []byte
	)
	counter := byte(1)
	for len(okm) < length {
		mac := hmac.New(sha256.New, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{counter})
		t = mac.Sum(nil)
		okm = append(okm, t...)
		counter++
	}
	return okm[:length]
}

// HKDF, ikm (input keying material) üzerinden info bağlamıyla length
// baytlık türetilmiş anahtar malzemesi üretir. salt boş bırakılabilir.
func HKDF(salt, ikm, info []byte, length int) []byte {
	prk := hkdfExtract(salt, ikm)
	return hkdfExpand(prk, info, length)
}
