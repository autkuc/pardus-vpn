package protocol

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"pardus-vpn/internal/cryptox"
)

// Session, başarılı bir el sıkışma sonrası kurulan çift yönlü taşıma
// oturumunu temsil eder. sendKey ile şifrelenen paketler karşı tarafta
// recvKey ile çözülür.
type Session struct {
	SessionID     uint32
	SendCounter   uint64
	sendAEAD      *cryptox.AEADSession
	recvAEAD      *cryptox.AEADSession
	Replay        ReplayGuard
	PeerStaticPub *ecdh.PublicKey
}

// NextSendCounter, bir sonraki giden paket için kullanılacak sayaç değerini
// döndürür ve iç sayaç durumunu ilerletir.
func (s *Session) NextSendCounter() uint64 {
	c := s.SendCounter
	s.SendCounter++
	return c
}

func (s *Session) Encrypt(plaintext []byte) (counter uint64, ciphertext []byte) {
	counter = s.NextSendCounter()
	return counter, s.sendAEAD.Seal(counter, plaintext)
}

func (s *Session) Decrypt(counter uint64, ciphertext []byte) ([]byte, error) {
	if err := s.Replay.Check(counter); err != nil {
		return nil, err
	}
	return s.recvAEAD.Open(counter, ciphertext)
}

// deriveTransportKeys, iki paylaşılan gizli (shared secret) değerinden
// HKDF ile iki yönlü taşıma anahtarlarını türetir. Her iki tarafın da aynı
// sırayla (sharedA || sharedB) çağırması ve rolüne göre doğru anahtarı
// (client->server / server->client) seçmesi gerekir.
func deriveTransportKeys(sharedA, sharedB []byte) (keyC2S, keyS2C []byte) {
	ikm := append(append([]byte{}, sharedA...), sharedB...)
	okm := cryptox.HKDF(nil, ikm, []byte("pardus-vpn transport-keys v1"), 64)
	return okm[:32], okm[32:64]
}

// ClientHandshakeInit, istemci tarafında el sıkışmanın ilk mesajını üretir.
// Döndürülen ephemeral anahtar çifti, yanıt işlenirken tekrar gerekecektir.
func ClientHandshakeInit(clientStatic *cryptox.KeyPair, serverStaticPub *ecdh.PublicKey) (msg []byte, ephemeral *cryptox.KeyPair, sharedA []byte, err error) {
	ephemeral, err = cryptox.GenerateKeyPair()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("geçici anahtar üretilemedi: %w", err)
	}

	sharedA, err = ephemeral.Private.ECDH(serverStaticPub)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ECDH (ephemeral, serverStatic) başarısız: %w", err)
	}

	tempKey := cryptox.HKDF(nil, sharedA, []byte("pardus-vpn handshake-init v1"), 32)
	tempAEAD, err := cryptox.NewAEADSession(tempKey)
	if err != nil {
		return nil, nil, nil, err
	}

	encStaticPub := tempAEAD.Seal(0, clientStatic.Public.Bytes())

	msg = make([]byte, HandshakeInitSize)
	msg[0] = TypeHandshakeInit
	copy(msg[1:1+PubKeySize], ephemeral.Public.Bytes())
	copy(msg[1+PubKeySize:], encStaticPub)

	return msg, ephemeral, sharedA, nil
}

// ServerProcessHandshakeInit, sunucu tarafında gelen ilk mesajı işler,
// istemcinin statik açık anahtarını doğrular (izinli peer listesine göre)
// ve yanıt mesajını üretir.
//
// isAllowed, çözülen istemci statik açık anahtarının izinli olup olmadığını
// kontrol eden bir geri çağrıdır (config'teki [Peer] listesine karşı).
func ServerProcessHandshakeInit(msg []byte, serverStatic *cryptox.KeyPair, isAllowed func(*ecdh.PublicKey) bool) (respMsg []byte, session *Session, clientStaticPub *ecdh.PublicKey, err error) {
	if len(msg) != HandshakeInitSize || msg[0] != TypeHandshakeInit {
		return nil, nil, nil, fmt.Errorf("geçersiz HandshakeInit mesajı (boyut=%d)", len(msg))
	}

	clientEphemeralPub, err := cryptox.PublicKeyFromBytes(msg[1 : 1+PubKeySize])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("istemci geçici açık anahtarı geçersiz: %w", err)
	}

	sharedA, err := serverStatic.Private.ECDH(clientEphemeralPub)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ECDH (serverStatic, clientEphemeral) başarısız: %w", err)
	}

	tempKey := cryptox.HKDF(nil, sharedA, []byte("pardus-vpn handshake-init v1"), 32)
	tempAEAD, err := cryptox.NewAEADSession(tempKey)
	if err != nil {
		return nil, nil, nil, err
	}

	encStaticPub := msg[1+PubKeySize:]
	staticPubRaw, err := tempAEAD.Open(0, encStaticPub)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("istemci statik anahtarı doğrulanamadı (yanlış anahtar veya sahte istek): %w", err)
	}

	clientStaticPub, err = cryptox.PublicKeyFromBytes(staticPubRaw)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("çözülen istemci statik anahtarı geçersiz: %w", err)
	}

	if isAllowed != nil && !isAllowed(clientStaticPub) {
		return nil, nil, nil, fmt.Errorf("istemci statik anahtarı izinli peer listesinde değil (yetkisiz bağlantı denemesi)")
	}

	serverEphemeral, err := cryptox.GenerateKeyPair()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("sunucu geçici anahtarı üretilemedi: %w", err)
	}

	sharedB, err := serverEphemeral.Private.ECDH(clientStaticPub)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ECDH (serverEphemeral, clientStatic) başarısız: %w", err)
	}

	keyC2S, keyS2C := deriveTransportKeys(sharedA, sharedB)

	sendAEAD, err := cryptox.NewAEADSession(keyS2C) // sunucu bu anahtarla şifreler
	if err != nil {
		return nil, nil, nil, err
	}
	recvAEAD, err := cryptox.NewAEADSession(keyC2S) // sunucu bu anahtarla çözer
	if err != nil {
		return nil, nil, nil, err
	}

	sessionID, err := randomUint32()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("oturum kimliği üretilemedi: %w", err)
	}

	session = &Session{
		SessionID:     sessionID,
		sendAEAD:      sendAEAD,
		recvAEAD:      recvAEAD,
		PeerStaticPub: clientStaticPub,
	}

	respMsg = make([]byte, HandshakeResponseSize)
	respMsg[0] = TypeHandshakeResponse
	copy(respMsg[1:1+PubKeySize], serverEphemeral.Public.Bytes())
	binary.BigEndian.PutUint32(respMsg[1+PubKeySize:], sessionID)

	return respMsg, session, clientStaticPub, nil
}

// ClientProcessHandshakeResponse, sunucudan gelen yanıtı işler ve nihai
// taşıma oturumunu (Session) kurar.
func ClientProcessHandshakeResponse(respMsg []byte, clientStatic *cryptox.KeyPair, clientEphemeral *cryptox.KeyPair, sharedA []byte) (*Session, error) {
	if len(respMsg) != HandshakeResponseSize || respMsg[0] != TypeHandshakeResponse {
		return nil, fmt.Errorf("geçersiz HandshakeResponse mesajı (boyut=%d)", len(respMsg))
	}

	serverEphemeralPub, err := cryptox.PublicKeyFromBytes(respMsg[1 : 1+PubKeySize])
	if err != nil {
		return nil, fmt.Errorf("sunucu geçici açık anahtarı geçersiz: %w", err)
	}
	sessionID := binary.BigEndian.Uint32(respMsg[1+PubKeySize:])

	sharedB, err := clientStatic.Private.ECDH(serverEphemeralPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH (clientStatic, serverEphemeral) başarısız: %w", err)
	}

	keyC2S, keyS2C := deriveTransportKeys(sharedA, sharedB)

	sendAEAD, err := cryptox.NewAEADSession(keyC2S) // istemci bu anahtarla şifreler
	if err != nil {
		return nil, err
	}
	recvAEAD, err := cryptox.NewAEADSession(keyS2C) // istemci bu anahtarla çözer
	if err != nil {
		return nil, err
	}

	return &Session{
		SessionID: sessionID,
		sendAEAD:  sendAEAD,
		recvAEAD:  recvAEAD,
	}, nil
}

func randomUint32() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}
