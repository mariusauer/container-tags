SHELL := /bin/bash

# Configurable variables
BIN ?= bin
BINARY ?= container-tags
CMD ?= ./cmd/container-tags
GOCACHE ?= $(CURDIR)/.gocache

export GOCACHE

.PHONY: all build run tidy test vet fmt clean

all: build

build:
	mkdir -p $(BIN)
	go build -v -o $(BIN)/$(BINARY) $(CMD)

# Usage: make run IMAGE=nginx
run: build
	$(BIN)/$(BINARY) $(IMAGE)

tidy:
	go mod tidy

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -s -w .

clean:
	rm -rf $(BIN) $(GOCACHE)

