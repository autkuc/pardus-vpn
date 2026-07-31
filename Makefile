.PHONY: all build server client genkey gui test vet fmt clean install

BIN_DIR := bin

all: build

build: server client genkey gui

server:
	go build -o $(BIN_DIR)/pardus-vpn-server ./cmd/server

client:
	go build -o $(BIN_DIR)/pardus-vpn-client ./cmd/client

genkey:
	go build -o $(BIN_DIR)/pardus-vpn-genkey ./cmd/genkey

gui:
	go build -o $(BIN_DIR)/pardus-vpn-gui ./cmd/gui

test:
	go test ./... -v

vet:
	go vet ./...

fmt:
	gofmt -w .

clean:
	rm -rf $(BIN_DIR)

install: build
	sudo ./scripts/install.sh
