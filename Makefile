all: build

godep-save:
	godep save

build:
	docker run --rm -it -v "$$GOPATH":/gopath -v "$$(pwd)":/app -e "GOPATH=/gopath" -w /app golang:1.6 sh -c 'go build -v github.com/sttts/etcd2-proxy-proxy'