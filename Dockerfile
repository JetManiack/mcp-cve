FROM golang:1.27-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags="-X main.version=${VERSION}" -o /bin/mcp-cve ./cmd/cve

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S -g 101 mcp && adduser -S -G mcp -u 100 mcp
COPY --from=builder /bin/mcp-cve /bin/mcp-cve
USER 100:101
EXPOSE 8080
ENTRYPOINT ["/bin/mcp-cve"]
