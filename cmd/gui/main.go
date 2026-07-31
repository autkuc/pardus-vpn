// Pardus VPN GUI.
//
// Yerel bir web sunucusu başlatır (varsayılan http://127.0.0.1:7777) ve
// tarayıcıda basit bir kontrol paneli sunar: Bağlan/Bağlantıyı Kes düğmesi,
// koyu/açık tema ve TR/EN dil seçeneği. Ağır bir GUI kütüphanesine
// (GTK/Qt) bağımlı olmamak için bilinçli olarak bu yaklaşım seçilmiştir.
//
// Kullanım:
//
//	sudo ./pardus-vpn-gui -config /etc/pardus-vpn/client.conf -addr 127.0.0.1:7777
//
// Ardından tarayıcıda http://127.0.0.1:7777 açılır.
package main

import (
	"embed"
	"encoding/json"
	"flag"
	"io/fs"
	"log"
	"net/http"

	"pardus-vpn/internal/vpnclient"
)

//go:embed webui/index.html
var webuiFS embed.FS

func main() {
	configPath := flag.String("config", "/etc/pardus-vpn/client.conf", "istemci config dosyasının yolu")
	addr := flag.String("addr", "127.0.0.1:7777", "GUI'nin dinleyeceği yerel adres")
	flag.Parse()

	mgr := vpnclient.NewManager(*configPath)

	sub, err := fs.Sub(webuiFS, "webui")
	if err != nil {
		log.Fatalf("gömülü arayüz dosyaları okunamadı: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(sub)))

	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, mgr.Status())
	})

	mux.HandleFunc("/api/connect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "sadece POST desteklenir", http.StatusMethodNotAllowed)
			return
		}
		go func() {
			if err := mgr.Connect(); err != nil {
				log.Printf("bağlantı hatası: %v", err)
			}
		}()
		writeJSON(w, map[string]string{"result": "connecting"})
	})

	mux.HandleFunc("/api/disconnect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "sadece POST desteklenir", http.StatusMethodNotAllowed)
			return
		}
		if err := mgr.Disconnect(); err != nil {
			log.Printf("bağlantı kesme hatası: %v", err)
		}
		writeJSON(w, map[string]string{"result": "disconnected"})
	})

	log.Printf("Pardus VPN GUI hazır: http://%s", *addr)
	log.Printf("config dosyası: %s", *configPath)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatalf("HTTP sunucusu başlatılamadı: %v", err)
	}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("JSON yazılamadı: %v", err)
	}
}
