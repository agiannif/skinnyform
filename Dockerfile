FROM golang:1-alpine AS builder
RUN apk add --no-cache ca-certificates
WORKDIR /tmp
COPY main.go .
RUN CGO_ENABLED=0 go build -ldflags '-w -s' -o skinnyform main.go

FROM scratch AS runner
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /tmp/skinnyform /
CMD ["/skinnyform"]
