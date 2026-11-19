FROM golang:1.27-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags="-X main.version=${VERSION}" -o /bin/mcp-cve ./cmd/cve

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S mcp && adduser -S -G mcp mcp
COPY --from=builder /bin/mcp-cve /bin/mcp-cve
USER mcp
EXPOSE 8080
ENTRYPOINT ["/bin/mcp-cve"]
