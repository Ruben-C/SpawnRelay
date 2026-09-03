VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
PLATFORMS := linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64 windows/amd64 windows/arm64 freebsd/amd64

.PHONY: build build-all clean test vet fmt run-server run-client

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/spawnrelay ./cmd/spawnrelay

# Cross-compile every platform into dist/. Raw binaries are what the server
# serves to clients at /dl/; the linux tarballs are what install-server.sh pulls.
build-all:
	@mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
		out=dist/spawnrelay_$${os}_$${arch}$$ext; \
		echo "  building $$out"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o $$out ./cmd/spawnrelay || exit 1; \
		if [ "$$os" = "linux" ]; then cp $$out dist/spawnrelay && tar -C dist -czf dist/spawnrelay_$${os}_$${arch}.tar.gz spawnrelay && rm dist/spawnrelay; fi; \
	done

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

clean:
	rm -rf bin dist

# Development helpers: run a server and a client on this machine.
run-server: build
	./bin/spawnrelay server --data-dir ./dev-data --tunnel-addr :7443 --admin-addr :8443 --public-host 127.0.0.1 --log-level debug

run-client: build
	./bin/spawnrelay client --env-file ./dev-data/client.env --log-level debug
