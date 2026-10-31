#!/bin/sh
# Build locally, ship the binary, restart the relay on koshkin.
set -e
cd "$(dirname "$0")"
go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o hop-linux .
scp hop-linux Dockerfile compose.yaml koshkin:/home/deploy/hopclip/
ssh koshkin 'cd /home/deploy/hopclip && docker compose up -d --build && docker compose ps'
