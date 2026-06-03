FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o sentinel .

FROM alpine:latest

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /build/sentinel /usr/local/bin/sentinel
COPY --from=builder /build/payloads /etc/sentinel/payloads

WORKDIR /data

ENTRYPOINT ["sentinel"]
CMD ["scan"]
