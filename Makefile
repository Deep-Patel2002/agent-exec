GO ?= go
CC ?= cc

.PHONY: build test race vet fmt-check seccomp integration clean
build:
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/agent-exec ./cmd/agent-exec
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/agent-exec-server ./cmd/agent-exec-server

test:
	$(GO) test -count=1 ./...

race:
	$(GO) test -race -count=1 ./...

vet:
	$(GO) vet ./...

fmt-check:
	test -z "$$(gofmt -l cmd internal)"

seccomp:
	mkdir -p bin
	$(CC) -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -O2 tools/seccompgen.c -lseccomp -o bin/seccompgen
	test ! -e bin/default.bpf
	bin/seccompgen bin/default.bpf

integration:
	bash tools/run-integration.sh

clean:
	$(GO) clean ./...
