// Package tuniface, Linux üzerinde /dev/net/tun aygıtını açıp yönetmek için
// düşük seviye bir arayüz sağlar. songgao/water gibi harici bir kütüphaneye
// bağımlı olmamak için ioctl çağrıları doğrudan "syscall" paketiyle yapılır.
package tuniface

import (
	"bytes"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	// linux/if.h ve linux/if_tun.h içindeki sabitler.
	ifNameSize = 16
	ifReqSize  = 40 // struct ifreq boyutu (amd64/arm64 üzerinde)

	iffTUN    = 0x0001
	iffNoPI   = 0x1000
	tunSetIFF = 0x400454ca // _IOW('T', 202, int)
)

// Interface, açık bir TUN aygıtını temsil eder.
type Interface struct {
	file *os.File
	Name string
}

// Create, verilen isimde (boşsa çekirdek "tunN" atar) bir TUN aygıtı açar.
// IFF_NO_PI bayrağı kullanıldığından, okunan/yazılan veriler ek bir paket
// bilgisi (packet info) başlığı olmadan doğrudan ham IP paketleridir.
//
// Bu işlem CAP_NET_ADMIN yetkisi (genellikle root) gerektirir.
func Create(name string) (*Interface, error) {
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("/dev/net/tun açılamadı (root/CAP_NET_ADMIN gerekli olabilir): %w", err)
	}

	var ifr [ifReqSize]byte
	nameBytes := []byte(name)
	if len(nameBytes) >= ifNameSize {
		syscall.Close(fd)
		return nil, fmt.Errorf("arayüz adı çok uzun (maksimum %d karakter): %q", ifNameSize-1, name)
	}
	copy(ifr[:ifNameSize], nameBytes)

	flags := uint16(iffTUN | iffNoPI)
	*(*uint16)(unsafe.Pointer(&ifr[ifNameSize])) = flags

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(tunSetIFF), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF ioctl başarısız: %v", errno)
	}

	createdName := string(bytes.TrimRight(ifr[:ifNameSize], "\x00"))

	if err := syscall.SetNonblock(fd, false); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("blocking modu ayarlanamadı: %w", err)
	}

	file := os.NewFile(uintptr(fd), "/dev/net/tun")
	return &Interface{file: file, Name: createdName}, nil
}

// Read, TUN aygıtından bir ham IP paketi okur.
func (i *Interface) Read(buf []byte) (int, error) {
	return i.file.Read(buf)
}

// Write, TUN aygıtına bir ham IP paketi yazar.
func (i *Interface) Write(buf []byte) (int, error) {
	return i.file.Write(buf)
}

// Close, TUN aygıtını kapatır.
func (i *Interface) Close() error {
	return i.file.Close()
}
