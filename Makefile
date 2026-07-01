.DEFAULT_GOAL := help

SERVER_BIN ?= anytls-server
CLIENT_BIN ?= anytls-client
SERVER_LISTEN ?= 0.0.0.0:8443
CLIENT_LISTEN ?= 127.0.0.1:1080
PASSWORD ?= password
SERVER_ADDR ?= 127.0.0.1:8443
TESTPKG ?= ./...
TESTRUN ?=

.PHONY: help build build-server build-client test vet check run-server run-client release clean

help: ## List all targets (default)
	@grep -E '^[a-zA-Z0-9_-]+:.*##' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-16s %s\n", $$1, $$2}'

build: build-server build-client ## Build server and client binaries

build-server: ## Build server binary
	go build -o $(SERVER_BIN) ./cmd/server

build-client: ## Build client binary
	go build -o $(CLIENT_BIN) ./cmd/client

test: ## Run tests (TESTPKG=./... TESTRUN=Name)
ifdef TESTRUN
	go test -run $(TESTRUN) $(TESTPKG)
else
	go test $(TESTPKG)
endif

vet: ## Run go vet
	go vet ./...

check: vet test ## Run vet and tests

run-server: ## Run server (go run; SERVER_LISTEN, PASSWORD, LOG_LEVEL)
ifdef LOG_LEVEL
	LOG_LEVEL=$(LOG_LEVEL) go run ./cmd/server -l $(SERVER_LISTEN) -p $(PASSWORD)
else
	go run ./cmd/server -l $(SERVER_LISTEN) -p $(PASSWORD)
endif

run-client: ## Run client (go run; CLIENT_LISTEN, SERVER_ADDR, PASSWORD, LOG_LEVEL)
ifdef LOG_LEVEL
	LOG_LEVEL=$(LOG_LEVEL) go run ./cmd/client -l $(CLIENT_LISTEN) -s "anytls://$(PASSWORD)@$(SERVER_ADDR)"
else
	go run ./cmd/client -l $(CLIENT_LISTEN) -s "anytls://$(PASSWORD)@$(SERVER_ADDR)"
endif

release: ## Local goreleaser snapshot into dist/
	goreleaser release --snapshot --clean

clean: ## Remove built binaries
	rm -f $(SERVER_BIN) $(CLIENT_BIN)
