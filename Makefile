.PHONY: proto proto-check dev build docker lint test helm-lint

proto:
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/alert.proto

# Fail if alert.proto has drifted from the shared contract hash (see
# scripts/check-proto-sync.sh). Keep muthur-collector and muthur in lockstep.
proto-check:
	./scripts/check-proto-sync.sh

dev:
	go run ./cmd/collector

build:
	CGO_ENABLED=0 go build -ldflags="-w -s" -trimpath -o bin/collector ./cmd/collector

docker:
	docker build -t muthur-collector:local .

lint:
	golangci-lint run ./...

test:
	go test ./... -v -race

helm-lint:
	helm lint helm/muthur-collector
