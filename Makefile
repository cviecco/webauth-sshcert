# Set GOPATH to a sensible default if not already set.
ifdef USERPROFILE
GOPATH ?= $(USERPROFILE)\go
else
GOPATH ?= $(HOME)/go
endif

all: build test

build:
	go build cmd/server/main.go
	go build cmd/client/main.go

get-deps:
	go get -t ./...

test:
	go test ./...

