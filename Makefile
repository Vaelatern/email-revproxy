.PHONY: build

build: email-revproxy

email-revproxy: main.go templates/ internal/
	go build .

clean:
	rm -f email-revproxy
