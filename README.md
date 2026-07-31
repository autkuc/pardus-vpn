Pardus Masaüstü ve Server kolay kullanılabilir VPN yazılımı




Saf Go WireGuard benzeri hızlı, güvenli VPN istemcisi/sunucusu

X25519 (ECDH) anahtar değişimi + AES-256-GCM (AEAD) şifreleme kullanılmaktadır. Kriptoloji kullanımı, peering ve TUN dahil her şey baştan Go ile yazılmıştır.

# Ekran Görüntüleri
![](https://github.com/autkuc/pardus-vpn/blob/main/screen/scr1.png?raw=true)
![](https://github.com/autkuc/pardus-vpn/blob/main/screen/scr2.png?raw=true)
---

# Kurulum
Adımlar root kullanıcısı/sudo kullanıldığı varsayılarak hazırlanmıştır.

## Bağlılıklar
`golang` meta paketi yüklü olmalıdır. Yüklemek için:
```bash
apt install golang
```

## Klonla

```bash
git clone https://github.com/autkuc/pardus-vpn
```
Güncel çıktılar `bin/` dosyasında sağlanmıştır.

Otomatik baştan kurmak için:

```bash
cd pardus-vpn
make build
```

## Anahtar çifti üretme
Kolaylık olması amacıyla `$PATH` değişkeninize pardus-vpn/bin ekleyebilirsiniz.

```bash
./bin/pardus-vpn-genkey
```

Sonuç olan çıkan iki anahtarı not alın.

# Ayarlama

## İstemci/Client
Kurulum bittikten sonra client.conf dosyasını aşağıdaki gibi düzenleyin:

```bash
nano /etc/pardus-vpn/client.conf
```

Karşınızdaki dosyada süslü parantezle belirtilmiş yerleri değiştirin:

```
[Interface]
PrivateKey = {ISTEMCI_OZEL_ANAHTARI} # Az önce ürettiğiniz PRIVATE_KEY'i yapıştırın
Address    = 10.8.0.2/24
DeviceName = pardus0
MTU        = 1420

[Peer]
PublicKey  = {SUNUCU_ACIK_ANAHTARI} # server'dan alacağınız (veya VPN hizmet sağlayıcısı) PUBLIC_KEY'i yapıştırın
Endpoint   = {SUNUCU_IP}:51820
AllowedIPs = 0.0.0.0/0
```
dosya örneklerine `configs/` klasöründen erişebilirsiniz.

Son olarak aşağıdaki komutu yürütün veya çalıştırma kısayoluna tıklayın ve arayüz http://localhost:7000 adresinde mevcut olacak:
```bash
./bin/pardus-vpn-gui
```

CLI/komut satırından kullanımı ve otomasyon için systemd de kullanılabilir:
```bash
systemctl enable --now pardus-vpn-client
```

> [!WARNING]  
> pardus-vpn-gui ve pardus-vpn-client aynı anda çalışmayacaktır.

## Sunucu/Server
Kurulum bittikten sonra server.conf dosyasını aşağıdaki gibi düzenleyin:

```bash
nano /etc/pardus-vpn/server.conf
```

Karşınızdaki dosyada süslü parantezle belirtilmiş yerleri değiştirin:

```
[Interface]
PrivateKey = {SUNUCU_OZEL_ANAHTARI}
Address    = 10.8.0.1/24
ListenPort = 51820
DeviceName = pardus0
MTU        = 1420

# Her istemci için ayrı bir [Peer] bölümü ekleyin.
[Peer]
PublicKey = ISTEMCI1_ACIK_ANAHTARINI_BURAYA_YAPISTIR
AllowedIPs = 10.8.0.2/32

[Peer]
PublicKey = ISTEMCI2_ACIK_ANAHTARINI_BURAYA_YAPISTIR
AllowedIPs = 10.8.0.3/32
```

Bağlanacak istemcilerin açık anahtarlarını (PUBLIC_KEY) sağlamanız gerekmektedir.

Sunucuyu çalıştırın:

```bash
systemctl enable --now pardus-vpn-server
```

systemd'nin sağlanamadığı bir ortamdaysanız manüel de çalıştırabilirsiniz:

```bash
./bin/pardus-vpn-server -config /etc/pardus-vpn/server.conf
```

Tüm internet trafiğinin tünelden geçirilmesi için kolaylık script'i de sunucuya sağlanmıştır, parantezi dış arayüz bağıntısıyla değiştirebilirsiniz:
```bash
./scripts/setup-nat.sh pardus0 {eth0/wlan0/...}
```

# Güvenlik

```bash
make test    # kriptografi/el sıkışma birim testleri
make vet     # statik analiz
```

# Hata Çözümleme

## TUN arayüzü oluşturulmadı: TUNSETIFF ioctl çalıştırılamadı: device or resource busy

İstemci'de gui ve cli'nin beraber çalışmadığından emin olun. İkisi birden açıksa kapatın:
```bash
systemctl stop pardus-vpn-client
```

kontrol:

```bash
ps aux | grep vpn
```
## TUN arayüzü bulunamadı
Çözümlemek için İstemci de halihazırda TUN cihazı bulunup bulunmadığından emin olun
```bash
ls -la /dev/net/tun
```

yoksa oluşturun:

```bash
mkdir -p /dev/net
mknod /dev/net/tun c 10 200
chmod 666 /dev/net/tun
```

manuel oluşturmak yerine tun modülünü kapatıp geri yüklemeyi tercih etmek isteyebilirsiniz:

```bash
modprobe tun
```

kontrol:

```bash
lsmod | grep tun
```
## Yetersiz izinler
Kullanıcının `netdev` de bulunduğundan emin olun:
```bash
sudo usermod -a -G netdev $USER
```
alternatif olarak root izniyle de çalıştırılabilir ve /etc/pardus-vpn dosyalarının chmod ayarlarını değiştirebilirsiniz. Dosya izinlerini değiştirirseniz güvenlik açısından izinsiz grupların erişemediğinden emin olun.

---

![Made with love in Turkey](https://madewithlove.now.sh/tr?heart=true&colorA=%23a4062e) | Apache License 2.0 
