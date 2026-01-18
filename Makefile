.PHONY: all build build-release build-release-amd run test test-coverage clean image push help

all: run

build:
	go build

build-release:
	go build -ldflags "-s -w"

build-release-amd:
	env GOOS=linux GOARCH=amd64 go build -ldflags "-s -w"

run:
	go run

test:
	go test -v

test-coverage:
	go test -v -cover -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html

clean:
	go clean
	rm -f skinnyform
	rm -f coverage.out coverage.html

image: clean
	docker build --platform=linux/amd64,linux/arm64 . -t agiannif/skinnyform:latest

push:
	docker push agiannif/skinnyform:latest

help:
	@echo "Usage: make [target]"
	@echo "Targets:"
	@echo "  all                  : run (default)"
	@echo "  build                : compile the project"
	@echo "  build-release        : compile without symbols"
	@echo "  build-release-amd    : compile for linux amd64"
	@echo "  run                  : run the project"
	@echo "  test                 : run tests"
	@echo "  test-coverage        : run tests with coverage report"
	@echo "  clean                : remove build objects and caches"
	@echo "  image                : build the docker image"
	@echo "  push                 : push image to docker"
