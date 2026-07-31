// genkey, config dosyalarında kullanılacak X25519 özel/açık anahtar
// çiftlerini üreten yardımcı komut satırı aracıdır.
//
// Kullanım:
//
//	./pardus-vpn-genkey
//
// Çıktı, doğrudan [Interface] PrivateKey alanına ve karşı tarafın
// [Peer] PublicKey alanına kopyalanabilecek şekilde iki satır olarak verilir.
package main

import (
	"fmt"
	"log"

	"pardus-vpn/internal/cryptox"
)

func main() {
	kp, err := cryptox.GenerateKeyPair()
	if err != nil {
		log.Fatalf("anahtar üretilemedi: %v", err)
	}
	fmt.Printf("PrivateKey = %s\n", kp.PrivateBase64())
	fmt.Printf("PublicKey  = %s\n", kp.PublicBase64())
}
