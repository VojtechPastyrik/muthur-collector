FROM golang:1.26.1-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" -trimpath \
    -o collector ./cmd/collector

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /app/collector /collector
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/collector"]
