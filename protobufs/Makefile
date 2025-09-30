PB = $(wildcard *.proto)
GO = $(PB:.proto=.pb.go)
PWD = $(pwd)

all: $(GO)

%.pb.go: %.proto
		protoc -I=. --go-grpc_out=paths=source_relative:. \
		--grpc-gateway_out . \
    --grpc-gateway_opt logtostderr=true \
    --grpc-gateway_opt paths=source_relative \
    --grpc-gateway_opt generate_unbound_methods=true \
		--go_out=paths=source_relative:. *.proto

clean:
		rm -f *.pb.go
