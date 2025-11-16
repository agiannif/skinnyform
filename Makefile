.PHONY: all build build-release build-release-amd run clean image push help

all: run

build:
	go build

build-release:
	go build -ldflags "-s -w"

build-release-amd:
	env GOOS=linux GOARCH=amd64 go build -ldflags "-s -w"

run:
	go run

clean:
	go clean
	rm -f skinnyform

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
	@echo "  clean                : remove build objects and caches"
	@echo "  image                : build the docker image"
	@echo "  push                 : push image to docker"
