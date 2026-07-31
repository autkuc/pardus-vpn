package protocol

import (
	"bytes"
	"crypto/ecdh"
	"testing"

	"pardus-vpn/internal/cryptox"
)

func TestFullHandshakeAndDataExchange(t *testing.T) {
	serverStatic, err := cryptox.GenerateKeyPair()
	if err != nil {
		t.Fatalf("sunucu anahtarı üretilemedi: %v", err)
	}
	clientStatic, err := cryptox.GenerateKeyPair()
	if err != nil {
		t.Fatalf("istemci anahtarı üretilemedi: %v", err)
	}

	// 1) İstemci HandshakeInit oluşturur.
	initMsg, clientEphemeral, sharedA, err := ClientHandshakeInit(clientStatic, serverStatic.Public)
	if err != nil {
		t.Fatalf("ClientHandshakeInit hata: %v", err)
	}

	// 2) Sunucu init mesajını işler ve yanıt üretir.
	isAllowed := func(pub *ecdh.PublicKey) bool {
		return cryptox.PublicKeyID(pub) == cryptox.PublicKeyID(clientStatic.Public)
	}
	respMsg, serverSession, gotClientPub, err := ServerProcessHandshakeInit(initMsg, serverStatic, isAllowed)
	if err != nil {
		t.Fatalf("ServerProcessHandshakeInit hata: %v", err)
	}
	if cryptox.PublicKeyID(gotClientPub) != cryptox.PublicKeyID(clientStatic.Public) {
		t.Fatalf("sunucu yanlış istemci açık anahtarını çözdü")
	}

	// 3) İstemci yanıtı işler.
	clientSession, err := ClientProcessHandshakeResponse(respMsg, clientStatic, clientEphemeral, sharedA)
	if err != nil {
		t.Fatalf("ClientProcessHandshakeResponse hata: %v", err)
	}
	if clientSession.SessionID != serverSession.SessionID {
		t.Fatalf("oturum kimlikleri uyuşmuyor: client=%d server=%d", clientSession.SessionID, serverSession.SessionID)
	}

	// 4) İstemci -> Sunucu veri şifreleme/çözme.
	plaintext := []byte("merhaba pardus vpn, bu bir test IP paketidir")
	counter, ciphertext := clientSession.Encrypt(plaintext)
	decrypted, err := serverSession.Decrypt(counter, ciphertext)
	if err != nil {
		t.Fatalf("sunucu çözme hatası: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("çözülen veri orijinaliyle eşleşmiyor: got=%q want=%q", decrypted, plaintext)
	}

	// 5) Sunucu -> İstemci veri şifreleme/çözme.
	reply := []byte("sunucudan yanit paketi")
	counter2, ciphertext2 := serverSession.Encrypt(reply)
	decrypted2, err := clientSession.Decrypt(counter2, ciphertext2)
	if err != nil {
		t.Fatalf("istemci çözme hatası: %v", err)
	}
	if !bytes.Equal(decrypted2, reply) {
		t.Fatalf("istemcide çözülen veri orijinaliyle eşleşmiyor: got=%q want=%q", decrypted2, reply)
	}

	// 6) Replay saldırısı tespiti: aynı counter tekrar gönderilirse reddedilmeli.
	if _, err := serverSession.Decrypt(counter, ciphertext); err == nil {
		t.Fatalf("replay saldırısı tespit edilemedi, aynı paket ikinci kez kabul edildi")
	}

	// 7) Yanlış statik anahtarlı istemci reddedilmeli (isAllowed=false durumu).
	rogueStatic, _ := cryptox.GenerateKeyPair()
	rogueInit, _, _, err := ClientHandshakeInit(rogueStatic, serverStatic.Public)
	if err != nil {
		t.Fatalf("rogue init oluşturulamadı: %v", err)
	}
	if _, _, _, err := ServerProcessHandshakeInit(rogueInit, serverStatic, isAllowed); err == nil {
		t.Fatalf("izinsiz istemci reddedilmedi")
	}
}
