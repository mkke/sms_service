GITINFO:=$(shell git rev-parse --short=8 HEAD)

sms_service: *.go
	GOOS=freebsd GOARCH=amd64 go build -ldflags="-X main.GitInfo=$(GITINFO)" sms_service.go smtp.go auth.go

install: sms_service
	scp sms_service root@gatekeeper:/root/

