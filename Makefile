BINARY := sentinel-sandbox-agent
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build release clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags='-s -w -X main.version=$(VERSION)' -o $(BINARY) .

release:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w -X main.version=$(VERSION)' -o $(BINARY)-linux-amd64 .
	sha256sum $(BINARY)-linux-amd64 > $(BINARY)-linux-amd64.sha256

clean:
	rm -f $(BINARY) $(BINARY)-linux-amd64 $(BINARY)-linux-amd64.sha256
