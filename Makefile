DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
VERSION := $(shell git describe --tags --exact-match 2>/dev/null || git branch --show-current)


certwarden-client:
	go build -ldflags "-s -w \
        -X main.Version=$(VERSION) \
        -X main.BuildDate=$(DATE)" \
         certwarden-client/cmd/certwarden-client 

.PHONY: test
test:
	go test -v ./...

.PHONY: all
all: certwarden-client