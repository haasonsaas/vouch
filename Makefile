.PHONY: build clean test install

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.Version=$(VERSION)"

build:
	@echo "Building vouch..."
	@mkdir -p bin
	go build $(LDFLAGS) -o bin/vouch-agent ./agent
	go build $(LDFLAGS) -o bin/vouch-server ./server
	go build $(LDFLAGS) -o bin/vouch ./cli

clean:
	rm -rf bin/ dist/

test:
	go test -v ./...

install: build
	cp bin/vouch-agent /usr/local/bin/
	cp bin/vouch-server /usr/local/bin/
	cp bin/vouch /usr/local/bin/

docker:
	docker build -t ghcr.io/haasonsaas/vouch-server:$(VERSION) -f Dockerfile.server .
	docker build -t ghcr.io/haasonsaas/vouch-agent:$(VERSION) -f Dockerfile.agent .
