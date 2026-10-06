.PHONY: all clean generate build test

all: generate build

generate:
	go generate ./pkg/probe/...

build:
	go build -o watch ./cmd/watch/
	go build -o verify ./cmd/verify/
	go build -o baseline ./cmd/baseline/
	go build -o simagent ./cmd/simagent/

test:
	go test -v ./...

clean:
	rm -f watch verify simagent baseline
	rm -f ground_truth.json trajectory.json
	rm -rf /tmp/agent-trace-demo
